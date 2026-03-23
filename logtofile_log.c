/*-------------------------------------------------------------------------
 *
 * logtofile_log.c
 *      Functions to write audit logs to file
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_log.h"

#include "logtofile_autoclose.h"
#include "logtofile_csv.h"
#include "logtofile_guc.h"
#include "logtofile_json.h"
#include "logtofile_shmem.h"
#include "logtofile_vars.h"

#include <lib/stringinfo.h>
#include <port/atomics.h>
#include <postmaster/syslogger.h>
#include <storage/fd.h>
#include <storage/ipc.h>
#include <storage/lwlock.h>
#include <storage/pg_shmem.h>
#include <storage/proc.h>
#include <utils/timestamp.h>
#include <utils/memutils.h>

#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <zlib.h>
#include <lz4frame.h>
#include <zstd.h>

/* Defines */
#define PGAUDIT_PREFIX_LINE "AUDIT: "
#define PGAUDIT_PREFIX_LINE_LENGTH sizeof(PGAUDIT_PREFIX_LINE) - 1

/*
 * We really want line-buffered mode for logfile output, but Windows does
 * not have it, and interprets _IOLBF as _IOFBF (bozos).  So use _IONBF
 * instead on Windows.
 */
#ifdef WIN32
#define LBF_MODE _IONBF
#else
#define LBF_MODE _IOLBF
#endif

/* variables to use only in this unit */
static char filename_in_use[MAXPGPATH];
static int autoclose_thread_status_debug = 0; // 0: new proc, 1: th running, 2: th running sleep used, 3: th closed
static uint32 pgaudit_ltf_local_rotation_generation = 0;
static z_stream *pgaudit_ltf_zstream = NULL;
static int pgaudit_ltf_gzip_level = 0;
static char *pgaudit_ltf_zbuf = NULL;
static uLong pgaudit_ltf_zbuf_len = 0;
static ZSTD_CCtx *pgaudit_ltf_zstd_cctx = NULL;

/* forward declaration private functions */
static void pgauditlogtofile_close_file(void);
static bool pgauditlogtofile_is_enabled(void);
static bool pgauditlogtofile_is_open_file(void);
static bool pgauditlogtofile_is_prefixed(const char *msg);
static bool pgauditlogtofile_open_file(void);
static bool pgauditlogtofile_record_audit(const ErrorData *edata, int exclude_nchars);
static bool pgauditlogtofile_write_audit(const ErrorData *edata, int exclude_nchars);

/* public methods */

/**
 * @brief Hook to emit_log - write the record to the audit or send it to the default logger
 * @param edata: error data
 * @return void
 */
void PgAuditLogToFile_emit_log(ErrorData *edata)
{
  int exclude_nchars = -1;

  if (pgauditlogtofile_is_enabled())
  {
    // printf("ENABLE PRINTF\n");
    if (pg_strncasecmp(edata->message, PGAUDIT_PREFIX_LINE, PGAUDIT_PREFIX_LINE_LENGTH) == 0)
    {
      exclude_nchars = PGAUDIT_PREFIX_LINE_LENGTH;
      edata->output_to_server = false;
    }
    else if (pgauditlogtofile_is_prefixed(edata->message))
    {
      edata->output_to_server = false;
      exclude_nchars = 0;
    }

    // Scenarios not contemplated above will be ignored
    if (exclude_nchars >= 0)
      pgauditlogtofile_record_audit(edata, exclude_nchars);
  }

  if (pgaudit_ltf_prev_emit_log_hook)
    pgaudit_ltf_prev_emit_log_hook(edata);
}

/* private functions */
/**
 * @brief Close the audit log file
 * @param void
 * @return void
 */
static void pgauditlogtofile_close_file(void)
{
  if (pgaudit_ltf_file_handler != -1)
  {
    close(pgaudit_ltf_file_handler);
    pgaudit_ltf_file_handler = -1;
  }
}

/**
 * @brief Checks if pgauditlogtofile is completely started and configured
 * @param void
 * @return bool - true if pgauditlogtofile is enabled
 */
static bool pgauditlogtofile_is_enabled(void)
{
  if (UsedShmemSegAddr == NULL)
    return false;

  if (!pgaudit_ltf_shm || !pg_atomic_unlocked_test_flag(&pgaudit_ltf_flag_shutdown) ||
      guc_pgaudit_ltf_log_directory == NULL || guc_pgaudit_ltf_log_filename == NULL ||
      strlen(guc_pgaudit_ltf_log_directory) == 0 || strlen(guc_pgaudit_ltf_log_filename) == 0)
    return false;

  return true;
}

/**
 * @brief Checks if the audit log file is open
 * @param void
 * @return bool - true if the file is open
 */
static bool pgauditlogtofile_is_open_file(void)
{
  if (pgaudit_ltf_file_handler != -1)
    return true;
  else
    return false;
}

/**
 * @brief Checks if a message starts with one of our intercept prefixes
 * @param msg: message
 * @return bool - true if the message starts with a prefix
 */
static bool pgauditlogtofile_is_prefixed(const char *msg)
{
  bool found = false;
  size_t i;

  if (guc_pgaudit_ltf_log_connections)
  {
    for (i = 0; !found && i < pgaudit_ltf_shm->num_prefixes_connection; i++)
    {
      found = pg_strncasecmp(msg, pgaudit_ltf_shm->prefixes_connection[i]->prefix, pgaudit_ltf_shm->prefixes_connection[i]->length) == 0;
    }
  }

  if (!found && guc_pgaudit_ltf_log_disconnections)
  {
    for (i = 0; !found && i < pgaudit_ltf_shm->num_prefixes_disconnection; i++)
    {
      found = pg_strncasecmp(msg, pgaudit_ltf_shm->prefixes_disconnection[i]->prefix, pgaudit_ltf_shm->prefixes_disconnection[i]->length) == 0;
    }
  }

  return found;
}

/**
 * @brief Open the audit log file
 * @param void
 * @return bool - true if the file was opened
 */
static bool pgauditlogtofile_open_file(void)
{
  mode_t oumask;
  bool opened = false;
  char shm_filename[MAXPGPATH];

  if (MyProc == NULL)
  {
    /* MyProc deinitialized, reuse filename_in_use */
    strlcpy(shm_filename, filename_in_use, MAXPGPATH);
  }
  else
  {
    LWLockAcquire(pgaudit_ltf_shm->lock, LW_SHARED);
    strlcpy(shm_filename, pgaudit_ltf_shm->filename, MAXPGPATH);
    LWLockRelease(pgaudit_ltf_shm->lock);
  }

  // if the filename is empty, we short-circuit
  if (strlen(shm_filename) == 0)
    return false;

  /* Create spool directory if not present; ignore errors */
  (void)MakePGDirectory(guc_pgaudit_ltf_log_directory);

  /*
   * Note we do not let guc_pgaudit_ltf_log_file_mode disable IWUSR, since we certainly want
   * to be able to write the files ourselves.
   */
  oumask = umask(
      (mode_t)((~(guc_pgaudit_ltf_log_file_mode | S_IWUSR)) & (S_IRWXU | S_IRWXG | S_IRWXO)));
  pgaudit_ltf_file_handler = open(shm_filename, O_CREAT | O_WRONLY | O_APPEND | PG_BINARY, guc_pgaudit_ltf_log_file_mode);
  umask(oumask);

  if (pgaudit_ltf_file_handler != -1)
  {
    opened = true;
    // File open, we update the filename we are using
    strcpy(filename_in_use, shm_filename);
  }
  else
  {
    ereport(LOG_SERVER_ONLY,
            (errcode_for_file_access(),
             errmsg("could not open log file \"%s\": %m", shm_filename)));
  }

  return opened;
}

/**
 * @brief Records an audit log
 * @param edata: error data
 * @param exclude_nchars: number of characters to exclude from the message
 * @return bool - true if the record was written
 */
static bool pgauditlogtofile_record_audit(const ErrorData *edata, int exclude_nchars)
{
  bool rc;
  char shm_filename[MAXPGPATH];
  uint32 current_generation;

  /* MyProc deinitialized and no current file - we cannot audit to file */
  if (MyProc == NULL && strlen(filename_in_use) == 0)
    return false;

  current_generation = pg_atomic_read_u32(&pgaudit_ltf_shm->rotation_generation);
  if (current_generation != pgaudit_ltf_local_rotation_generation || strlen(filename_in_use) == 0)
  {
    pgauditlogtofile_close_file();

    LWLockAcquire(pgaudit_ltf_shm->lock, LW_SHARED);
    strlcpy(shm_filename, pgaudit_ltf_shm->filename, MAXPGPATH);
    LWLockRelease(pgaudit_ltf_shm->lock);

    pgaudit_ltf_local_rotation_generation = current_generation;

    ereport(DEBUG3, (errmsg("pgauditlogtofile record audit file handler requires reopening - shm_filename %s filename_in_use %s",
                            shm_filename, filename_in_use)));
  }

  if (!pgauditlogtofile_is_open_file() && !pgauditlogtofile_open_file())
    return false;

  rc = pgauditlogtofile_write_audit(edata, exclude_nchars);
  pgaudit_ltf_autoclose_active_ts = GetCurrentTimestamp();

  if (guc_pgaudit_ltf_auto_close_minutes > 0)
  {
    // only 1 auto-close thread
    if (pg_atomic_test_set_flag(&pgaudit_ltf_autoclose_flag_thread))
    {
      ereport(DEBUG3, (errmsg("pgauditlogtofile record_audit - create autoclose thread")));
      autoclose_thread_status_debug = 1;
      pthread_attr_init(&pgaudit_ltf_autoclose_thread_attr);
      pthread_attr_setdetachstate(&pgaudit_ltf_autoclose_thread_attr, PTHREAD_CREATE_DETACHED);
      pthread_create(&pgaudit_ltf_autoclose_thread, &pgaudit_ltf_autoclose_thread_attr, PgAuditLogToFile_autoclose_run, &autoclose_thread_status_debug);
    }
  }

  return rc;
}

/**
 * @brief Writes an audit record in the audit log file
 * @param edata: error data
 * @param exclude_nchars: number of characters to exclude from the message
 */
static bool pgauditlogtofile_write_audit(const ErrorData *edata, int exclude_nchars)
{
  StringInfoData buf;
  bool success = false;
  bool compression_success = true;
  char *data_to_write;
  int rc = 0;

  initStringInfo(&buf);
  /* create the log line */
  switch (guc_pgaudit_ltf_log_format)
  {
  case PGAUDIT_LTF_FORMAT_CSV:
    PgAuditLogToFile_csv_audit(&buf, edata, exclude_nchars);
    break;
  case PGAUDIT_LTF_FORMAT_JSON:
    PgAuditLogToFile_json_audit(&buf, edata, exclude_nchars);
    break;
  }

  // auto-close maybe has closed the file
  if (pgaudit_ltf_file_handler == -1)
    pgauditlogtofile_open_file();

  data_to_write = buf.data;

  if (pgaudit_ltf_file_handler != -1)
  {
    if (guc_pgaudit_ltf_log_compression != PGAUDIT_LTF_COMPRESSION_OFF)
    {
      size_t compressed_len_bound = 0;

      /* Calculate buffer size */
      switch (guc_pgaudit_ltf_log_compression)
      {
      case PGAUDIT_LTF_COMPRESSION_GZIP:
        compressed_len_bound = compressBound(buf.len);
        break;
      case PGAUDIT_LTF_COMPRESSION_LZ4:
        compressed_len_bound = LZ4F_compressFrameBound(buf.len, NULL);
        break;
      case PGAUDIT_LTF_COMPRESSION_ZSTD:
        compressed_len_bound = ZSTD_compressBound(buf.len);
        break;
      }

      /* Ensure buffer is large enough */
      if (pgaudit_ltf_zbuf == NULL || pgaudit_ltf_zbuf_len < compressed_len_bound)
      {
        if (pgaudit_ltf_zbuf)
          pfree(pgaudit_ltf_zbuf);
        pgaudit_ltf_zbuf_len = compressed_len_bound;
        pgaudit_ltf_zbuf = (char *)MemoryContextAlloc(TopMemoryContext, pgaudit_ltf_zbuf_len);
      }

      /* Compress */
      switch (guc_pgaudit_ltf_log_compression)
      {
      case PGAUDIT_LTF_COMPRESSION_GZIP:
      {
        int ret;
        int level = guc_pgaudit_ltf_log_compression_level;

        if (level == 0)
          level = Z_BEST_SPEED;
        else if (level > 9)
          level = 9;

        if (pgaudit_ltf_zstream != NULL && pgaudit_ltf_gzip_level != level)
        {
          deflateEnd(pgaudit_ltf_zstream);
          pfree(pgaudit_ltf_zstream);
          pgaudit_ltf_zstream = NULL;
        }

        if (pgaudit_ltf_zstream == NULL)
        {
          pgaudit_ltf_zstream = (z_stream *)MemoryContextAlloc(TopMemoryContext, sizeof(z_stream));
          pgaudit_ltf_zstream->zalloc = Z_NULL;
          pgaudit_ltf_zstream->zfree = Z_NULL;
          pgaudit_ltf_zstream->opaque = Z_NULL;
          ret = deflateInit2(pgaudit_ltf_zstream, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
          if (ret != Z_OK)
          {
            ereport(LOG_SERVER_ONLY, (errmsg("pgauditlogtofile: could not initialize compression stream: zlib error %d", ret)));
            pfree(pgaudit_ltf_zstream);
            pgaudit_ltf_zstream = NULL;
            compression_success = false;
          }
          else
          {
            pgaudit_ltf_gzip_level = level;
          }
        }
        else
        {
          deflateReset(pgaudit_ltf_zstream);
        }

        if (pgaudit_ltf_zstream)
        {
          pgaudit_ltf_zstream->avail_in = buf.len;
          pgaudit_ltf_zstream->next_in = (Bytef *)buf.data;
          pgaudit_ltf_zstream->avail_out = pgaudit_ltf_zbuf_len;
          pgaudit_ltf_zstream->next_out = (Bytef *)pgaudit_ltf_zbuf;

          ret = deflate(pgaudit_ltf_zstream, Z_FINISH);
          if (ret != Z_STREAM_END)
          {
            ereport(LOG_SERVER_ONLY, (errmsg("pgauditlogtofile: could not compress audit record: zlib error %d", ret)));
            compression_success = false;
          }
          else
          {
            buf.len = pgaudit_ltf_zstream->total_out;
            data_to_write = pgaudit_ltf_zbuf;
          }
        }
        break;
      }
      case PGAUDIT_LTF_COMPRESSION_LZ4:
      {
        LZ4F_preferences_t prefs;
        size_t cSize;
        memset(&prefs, 0, sizeof(prefs));
        prefs.compressionLevel = guc_pgaudit_ltf_log_compression_level;
        cSize = LZ4F_compressFrame(pgaudit_ltf_zbuf, pgaudit_ltf_zbuf_len, buf.data, buf.len, &prefs);
        if (LZ4F_isError(cSize))
        {
          ereport(LOG_SERVER_ONLY, (errmsg("pgauditlogtofile: could not compress audit record: lz4 error %s", LZ4F_getErrorName(cSize))));
          compression_success = false;
        }
        else
        {
          buf.len = cSize;
          data_to_write = pgaudit_ltf_zbuf;
        }
        break;
      }
      case PGAUDIT_LTF_COMPRESSION_ZSTD:
      {
        size_t cSize;
        int level = guc_pgaudit_ltf_log_compression_level;
        if (level == 0)
          level = 1;

        if (pgaudit_ltf_zstd_cctx == NULL)
        {
          pgaudit_ltf_zstd_cctx = ZSTD_createCCtx();
        }
        cSize = ZSTD_compressCCtx(pgaudit_ltf_zstd_cctx, pgaudit_ltf_zbuf, pgaudit_ltf_zbuf_len, buf.data, buf.len, level);
        if (ZSTD_isError(cSize))
        {
          ereport(LOG_SERVER_ONLY, (errmsg("pgauditlogtofile: could not compress audit record: zstd error %s", ZSTD_getErrorName(cSize))));
          compression_success = false;
        }
        else
        {
          buf.len = cSize;
          data_to_write = pgaudit_ltf_zbuf;
        }
        break;
      }
      default:
        break;
      }
    }

    if (compression_success)
    {
      rc = write(pgaudit_ltf_file_handler, data_to_write, buf.len);
      if (rc == buf.len)
      {
        success = true;
      }
      else
      {
        ereport(LOG_SERVER_ONLY,
                (errcode_for_file_access(),
                 errmsg("could not write audit log file \"%s\": %m", filename_in_use)));
        pgauditlogtofile_close_file();
      }
    }
  }

  /* failed write, do it on server here because the original log record has been modified in place */
  if (!success)
    ereport(LOG_SERVER_ONLY, (errmsg("%s", buf.data)));

  pfree(buf.data);

  return success;
}