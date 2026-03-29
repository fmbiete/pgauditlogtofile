/*-------------------------------------------------------------------------
 *
 * logtofile_shmem.c
 *      Functions to manage shared memory
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_shmem.h"

#include <miscadmin.h>
#include <storage/pg_shmem.h>
#include <storage/shmem.h>
#include <utils/memutils.h>
#include <utils/timestamp.h>

#include <time.h>

#include "logtofile_connect.h"
#include "logtofile_filename.h"
#include "logtofile_guc.h"
#include "logtofile_vars.h"

/* Extracted from src/backend/po */
static const char *postgresConnMsg[] = {
    "connection received: host=%s port=%s",
    "connection received: host=%s",
    "connection authorized: user=%s",
    "connection authenticated: identity=\"%s\" method=%s (%s:%d)",
    "connection authenticated: user=\"%s\" method=%s (%s:%d)",
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
    "role \"%s\" does not exist",
    "connection ready: setup total=%.3f ms, fork=%.3f ms, authentication=%.3f ms",
};

/* Extracted from src/backend/po */
static const char *postgresDisconnMsg[] = {
    "disconnection: session time: %d:%02d:%02d.%03d user=%s database=%s host=%s%s%s"};

/* forward declaration private functions */
static void pgauditlogtofile_init_prefixes(PgAuditLogToFilePrefix ***shm_ptr,
                                           size_t *shm_count,
                                           const char **messages,
                                           size_t num_messages);
static size_t pgauditlogtofile_shmem_size(void);

/**
 * @brief Request shared memory space
 */
void PgAuditLogToFile_shmem_request(void)
{
#if (PG_VERSION_NUM >= 150000)
  if (pgaudit_ltf_prev_shmem_request_hook)
    pgaudit_ltf_prev_shmem_request_hook();
#endif

  RequestAddinShmemSpace(pgauditlogtofile_shmem_size());
  RequestNamedLWLockTranche("pgauditlogtofile", 1);
}

/**
 * @brief SHMEM startup hook - Initialize SHMEM structure
 */
void PgAuditLogToFile_shmem_startup(void)
{
  bool found;

  if (pgaudit_ltf_prev_shmem_startup_hook)
    pgaudit_ltf_prev_shmem_startup_hook();

  /* reset in case this is a restart within the postmaster */
  pgaudit_ltf_shm = NULL;

  LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);
  pgaudit_ltf_shm = ShmemInitStruct("pgauditlogtofile", sizeof(PgAuditLogToFileShm), &found);
  if (!found)
  {
    pg_atomic_init_flag(&pgaudit_ltf_flag_shutdown);

    pgauditlogtofile_init_prefixes(&pgaudit_ltf_shm->prefixes_connection,
                                   &pgaudit_ltf_shm->num_prefixes_connection,
                                   postgresConnMsg,
                                   sizeof(postgresConnMsg) / sizeof(char *));

    pgauditlogtofile_init_prefixes(&pgaudit_ltf_shm->prefixes_disconnection,
                                   &pgaudit_ltf_shm->num_prefixes_disconnection,
                                   postgresDisconnMsg,
                                   sizeof(postgresDisconnMsg) / sizeof(char *));

    pgaudit_ltf_shm->lock = &(GetNamedLWLockTranche("pgauditlogtofile"))->lock;
    pg_atomic_init_u32(&pgaudit_ltf_shm->rotation_generation, 0);
    PgAuditLogToFile_calculate_current_filename();
    PgAuditLogToFile_set_next_rotation_time();
  }
  LWLockRelease(AddinShmemInitLock);

  if (!IsUnderPostmaster)
    on_shmem_exit(PgAuditLogToFile_shmem_shutdown, (Datum)0);

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

  LWLockAcquire(pgaudit_ltf_shm->lock, LW_EXCLUSIVE);
  memset(pgaudit_ltf_shm->filename, 0, sizeof(pgaudit_ltf_shm->filename));
  strcpy(pgaudit_ltf_shm->filename, filename);
  LWLockRelease(pgaudit_ltf_shm->lock);

  /* increase generation */
  if (pg_atomic_read_u32(&pgaudit_ltf_shm->rotation_generation) == PG_UINT32_MAX)
    pg_atomic_write_u32(&pgaudit_ltf_shm->rotation_generation, 0);
  else
    pg_atomic_add_fetch_u32(&pgaudit_ltf_shm->rotation_generation, 1);

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

  now = (pg_time_t)time(NULL);
  if (now >= pgaudit_ltf_shm->next_rotation_time)
  {
    ereport(DEBUG3, (errmsg("pgauditlogtofile needs to rotate file %s", pgaudit_ltf_shm->filename)));
    return true;
  }

  return false;
}

/* private functions */
/**
 * @brief Helper to initialize a prefix list in shared memory
 */
static void
pgauditlogtofile_init_prefixes(PgAuditLogToFilePrefix ***shm_ptr,
                               size_t *shm_count,
                               const char **messages,
                               size_t num_messages)
{
  char **prefixes;
  size_t num_unique;
  size_t i;

  prefixes = PgAuditLogToFile_connect_UniquePrefixes(messages, num_messages, &num_unique);
  *shm_count = num_unique;
  *shm_ptr = (PgAuditLogToFilePrefix **)ShmemAlloc(num_unique * sizeof(PgAuditLogToFilePrefix *));

  for (i = 0; i < num_unique; i++)
  {
    size_t len = strlen(prefixes[i]);

    (*shm_ptr)[i] = (PgAuditLogToFilePrefix *)ShmemAlloc(sizeof(PgAuditLogToFilePrefix));
    (*shm_ptr)[i]->length = (int)len;
    (*shm_ptr)[i]->prefix = (char *)ShmemAlloc(len + 1);
    memcpy((*shm_ptr)[i]->prefix, prefixes[i], len + 1);
    pfree(prefixes[i]);
  }
  pfree(prefixes);
}

/**
 * @brief Calculate total shared memory required
 */
static size_t
pgauditlogtofile_shmem_size(void)
{
  size_t size;
  size_t i;
  size_t conn_count = sizeof(postgresConnMsg) / sizeof(char *);
  size_t disconn_count = sizeof(postgresDisconnMsg) / sizeof(char *);

  size = MAXALIGN(sizeof(PgAuditLogToFileShm));

  /*
   * Reserve worst-case space for all static strings.
   * This avoids double-calling the deduplication logic.
   */
  size = add_size(size, mul_size(conn_count, sizeof(PgAuditLogToFilePrefix *)));
  for (i = 0; i < conn_count; i++)
  {
    size = add_size(size, MAXALIGN(sizeof(PgAuditLogToFilePrefix)));
    size = add_size(size, MAXALIGN(strlen(postgresConnMsg[i]) + 1));
  }

  size = add_size(size, mul_size(disconn_count, sizeof(PgAuditLogToFilePrefix *)));
  for (i = 0; i < disconn_count; i++)
  {
    size = add_size(size, MAXALIGN(sizeof(PgAuditLogToFilePrefix)));
    size = add_size(size, MAXALIGN(strlen(postgresDisconnMsg[i]) + 1));
  }

  return size;
}