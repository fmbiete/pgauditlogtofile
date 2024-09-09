/*-------------------------------------------------------------------------
 *
 * logtofile_shmem.c
 *      Functions to manage shared memory
 *
 * Copyright (c) 2020-2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_shmem.h"

#include <miscadmin.h>
#include <storage/pg_shmem.h>
#include <storage/shmem.h>
#include <utils/timestamp.h>
#include <sys/time.h>

#include <time.h>

#include "logtofile_autoclose.h"
#include "logtofile_connect.h"
#include "logtofile_filename.h"
#include "logtofile_guc.h"
#include "logtofile_vars.h"

/* Extracted from src/backend/po */
const char *postgresConnMsg[] = {
    "connection received: host=%s port=%s",
    "connection received: host=%s",
    "connection authorized: user=%s",
    "connection authenticated: identity=\"%s\" method=%s (%s:%d)",
    "replication connection authorized: user=%s",
    "replication connection authorized: user=%s SSL enabled (protocol=%s, cipher=%s, bits=%d, compression=%s)",
    "replication connection authorized: user=%s application_name=%s",
    "replication connection authorized: user=%s application_name=%s SSL enabled (protocol=%s, cipher=%s, bits=%d, compression=%s)",
    "password authentication failed for user \"%s\"",
    "authentication failed for user \"%s\": host rejected",
    "\"trust\" authentication failed for user \"%s\"",
    "Ident authentication failed for user \"%s\"",
    "Peer authentication failed for user \"%s\"",
    "password authentication failed for user \"%s\"",
    "SSPI authentication failed for user \"%s\"",
    "PAM authentication failed for user \"%s\"",
    "BSD authentication failed for user \"%s\"",
    "LDAP authentication failed for user \"%s\"",
    "certificate authentication failed for user \"%s\"",
    "RADIUS authentication failed for user \"%s\"",
    "authentication failed for user \"%s\": invalid authentication method",
    "connection authorized: user=%s database=%s",
    "connection authorized: user=%s database=%s SSL enabled (protocol=%s, cipher=%s, bits=%d, compression=%s)",
    "connection authorized: user=%s database=%s application_name=%s",
    "connection authorized: user=%s database=%s application_name=%s SSL enabled (protocol=%s, cipher=%s, bits=%d, compression=%s)",
};

/* Extracted from src/backend/po */
const char *postgresDisconnMsg[] = {
    "disconnection: session time: %d:%02d:%02d.%03d user=%s database=%s host=%s%s%s"};

// Private functions
Timestamp pgauditlogtofile_truncate_timestamp(Timestamp t);

#if (PG_VERSION_NUM >= 150000)
/**
 * @brief Request shared memory space
 * @param void
 * @return void
*/
void PgAuditLogToFile_shmem_request(void)
{
  if (prev_shmem_request_hook)
    prev_shmem_request_hook();

  RequestAddinShmemSpace(MAXALIGN(sizeof(PgAuditLogToFileShm)));
  RequestNamedLWLockTranche("pgauditlogtofile", 1);
}
#endif

/**
 * @brief SHMEM startup hook - Initialize SHMEM structure
 * @param void
 * @return void
 */
void PgAuditLogToFile_shmem_startup(void)
{
  bool found;
  size_t num_messages, i, j;
  char **prefixes = NULL;

  // Execute other hooks
  if (prev_shmem_startup_hook)
    prev_shmem_startup_hook();

  /* reset in case this is a restart within the postmaster */
  pgaudit_ltf_shm = NULL;

  LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);
  pgaudit_ltf_shm = ShmemInitStruct("pgauditlogtofile", sizeof(PgAuditLogToFileShm), &found);
  if (!found)
  {
    pg_atomic_init_flag(&pgaudit_ltf_flag_shutdown);
    // Get unique prefixes and copy them to SHMEM
    num_messages = sizeof(postgresConnMsg) / sizeof(char *);
    prefixes = PgAuditLogToFile_connect_UniquePrefixes(postgresConnMsg, num_messages, &pgaudit_ltf_shm->num_prefixes_connection);
    pgaudit_ltf_shm->prefixes_connection = ShmemAlloc(pgaudit_ltf_shm->num_prefixes_connection * sizeof(PgAuditLogToFilePrefix *));
    for (i = 0, j = 0; i < num_messages; i++)
    {
      if (prefixes != NULL && prefixes[i] != NULL)
      {
        pgaudit_ltf_shm->prefixes_connection[j] = ShmemAlloc(sizeof(PgAuditLogToFilePrefix));
        pgaudit_ltf_shm->prefixes_connection[j]->length = strlen(prefixes[i]);
        pgaudit_ltf_shm->prefixes_connection[j]->prefix = ShmemAlloc((pgaudit_ltf_shm->prefixes_connection[j]->length + 1) * sizeof(char));
        strcpy(pgaudit_ltf_shm->prefixes_connection[j]->prefix, prefixes[i]);
        pfree(prefixes[i]);
        j++;
      }
    }
    pfree(prefixes);

    num_messages = sizeof(postgresDisconnMsg) / sizeof(char *);
    prefixes = PgAuditLogToFile_connect_UniquePrefixes(postgresDisconnMsg, num_messages, &pgaudit_ltf_shm->num_prefixes_disconnection);
    pgaudit_ltf_shm->prefixes_disconnection = ShmemAlloc(pgaudit_ltf_shm->num_prefixes_disconnection * sizeof(PgAuditLogToFilePrefix *));
    for (i = 0, j = 0; i < num_messages; i++)
    {
      if (prefixes != NULL && prefixes[i] != NULL)
      {
        pgaudit_ltf_shm->prefixes_disconnection[j] = ShmemAlloc(sizeof(PgAuditLogToFilePrefix));
        pgaudit_ltf_shm->prefixes_disconnection[j]->length = strlen(prefixes[i]);
        pgaudit_ltf_shm->prefixes_disconnection[j]->prefix = ShmemAlloc((pgaudit_ltf_shm->prefixes_disconnection[j]->length + 1) * sizeof(char));
        strcpy(pgaudit_ltf_shm->prefixes_disconnection[j]->prefix, prefixes[i]);
        pfree(prefixes[i]);
        j++;
      }
    }
    pfree(prefixes);

    pgaudit_ltf_shm->lock = &(GetNamedLWLockTranche("pgauditlogtofile"))->lock;    
    PgAuditLogToFile_calculate_current_filename();
    PgAuditLogToFile_set_next_rotation_time();

    // Initial worker latch
    pgaudit_ltf_shm->worker_latch = NULL;
    // Initial global log file memory counter
    pgaudit_ltf_shm->total_written_bytes = 0;
  }
  LWLockRelease(AddinShmemInitLock);

  if (IsUnderPostmaster)
  {
    // Backend
    pg_atomic_init_flag(&pgaudit_ltf_autoclose_flag_thread);
  }
  else
  {
    // Postmaster
    on_shmem_exit(PgAuditLogToFile_shmem_shutdown, (Datum)0);
  }

  if (!found)
    ereport(LOG, (errmsg("pgauditlogtofile extension initialized")));
}

/**
 * @brief SHMEM shutdown hook
 * @param code: code
 * @param arg: arg
 * @return void
 */
void PgAuditLogToFile_shmem_shutdown(int code, Datum arg)
{
  pg_atomic_test_set_flag(&pgaudit_ltf_flag_shutdown);
}

/**
 * @brief Generates the name for the audit log file
 * @param void
 * @return void
 */
void PgAuditLogToFile_calculate_current_filename(void)
{
  char *filename = NULL;

  if (UsedShmemSegAddr == NULL || pgaudit_ltf_shm == NULL)
    return;

  filename = PgAuditLogToFile_current_filename();
  if (filename == NULL)
  {
    ereport(WARNING, (errmsg("pgauditlogtofile failed to calculate filename")));
    return;
  }

  if(guc_pgaudit_ltf_log_rotation_size > 0)
  {
      char *last_dot = NULL;
      size_t prefix_len;

      last_dot = strrchr(filename, '.');
      if (last_dot != NULL)
      {
        prefix_len = last_dot - filename;
      }
      else
      {
        last_dot = filename;
        prefix_len = sizeof(filename);
      }

      LWLockAcquire(pgaudit_ltf_shm->lock, LW_EXCLUSIVE);
      if (strncmp(filename, pgaudit_ltf_shm->filename, prefix_len) == 0)
      {
        struct timeval tv;
        int microseconds;

        gettimeofday(&tv, NULL);

        microseconds = tv.tv_usec;

        if (last_dot != NULL)
        {
            char new_filename[MAXPGPATH];

            strncpy(new_filename, filename, prefix_len);
            new_filename[prefix_len] = '\0';

            snprintf(new_filename + prefix_len, sizeof(new_filename) - prefix_len, "_%d%s", microseconds, last_dot);

            memset(pgaudit_ltf_shm->filename, 0, sizeof(pgaudit_ltf_shm->filename));
            strcpy(pgaudit_ltf_shm->filename, new_filename);
        }
        else
        {
            snprintf(pgaudit_ltf_shm->filename, sizeof(pgaudit_ltf_shm->filename), "%s_%d", filename, microseconds);

        }
      }
      else
      {
        if (last_dot != NULL)
        {
            char new_filename[MAXPGPATH];

            strncpy(new_filename, filename, prefix_len);
            new_filename[prefix_len] = '\0';

            snprintf(new_filename + prefix_len, sizeof(new_filename) - prefix_len, "_%d%s", 0, last_dot);

            memset(pgaudit_ltf_shm->filename, 0, sizeof(pgaudit_ltf_shm->filename));
            strcpy(pgaudit_ltf_shm->filename, new_filename);
        }
        else
        {
            snprintf(pgaudit_ltf_shm->filename, sizeof(pgaudit_ltf_shm->filename), "%s_%d", filename, 0);
        }
      }
      LWLockRelease(pgaudit_ltf_shm->lock);
  }
  else
  {
    LWLockAcquire(pgaudit_ltf_shm->lock, LW_EXCLUSIVE);
    memset(pgaudit_ltf_shm->filename, 0, sizeof(pgaudit_ltf_shm->filename));
    strcpy(pgaudit_ltf_shm->filename, filename);
    LWLockRelease(pgaudit_ltf_shm->lock);
  }

  pfree(filename);
}

/*
 * @brief Checks if the audit log file needs to be rotated before we use it
 * @param void
 * @return bool: true if the file needs to be rotated
 */
bool PgAuditLogToFile_needs_rotate_file(void)
{
  pg_time_t now;

  if (UsedShmemSegAddr == NULL || pgaudit_ltf_shm == NULL)
    return false;

  if (guc_pgaudit_ltf_log_rotation_age < 1)
    return false;

  if((guc_pgaudit_ltf_log_rotation_size > 0) && pgaudit_ltf_shm->size_rotation_flag)
  {
    ereport(DEBUG3, (errmsg("pgauditlogtofile needs to rotate file %s", pgaudit_ltf_shm->filename)));
    return true;
  }

  now = (pg_time_t) time(NULL);
	if (now >= pgaudit_ltf_shm->next_rotation_time)
  {
    ereport(DEBUG3, (errmsg("pgauditlogtofile needs to rotate file %s", pgaudit_ltf_shm->filename)));
    return true;
  }

  return false;
}