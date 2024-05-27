#include "logtofile_shmem.h"

#include <miscadmin.h>
#include <storage/pg_shmem.h>
#include <storage/shmem.h>
#include <utils/timestamp.h>

#include <time.h>

#include "logtofile_autoclose.h"
#include "logtofile_connect.h"
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
void PgAuditLogToFile_shmem_request(void)
{
  if (prev_shmem_request_hook)
    prev_shmem_request_hook();

  RequestAddinShmemSpace(MAXALIGN(sizeof(PgAuditLogToFileShm)));
  RequestNamedLWLockTranche("pgauditlogtofile", 1);
}
#endif

/*
 * SHMEM startup hook - Initialize SHMEM structure
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
    if (guc_pgaudit_ltf_log_rotation_age > 0)
      PgAuditLogToFile_calculate_next_rotation_time();
    PgAuditLogToFile_calculate_filename();
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

/*
 * Identify when we are doing a shutdown
 */
void PgAuditLogToFile_shmem_shutdown(int code, Datum arg)
{
  pg_atomic_test_set_flag(&pgaudit_ltf_flag_shutdown);
}

/*
 * Generates the name for the audit log file
 */
void PgAuditLogToFile_calculate_filename(void)
{
  int len;
  struct pg_tm tm;
  fsec_t fsec;

  if (UsedShmemSegAddr == NULL || pgaudit_ltf_shm == NULL)
    return;

  if (timestamp2tm(pgauditlogtofile_truncate_timestamp(GetCurrentTimestamp()), NULL, &tm, &fsec, NULL, NULL) != 0)
  {
    ereport(WARNING, errmsg("pgauditlogtofile failed calculate_filename - conversion to tm"));
    return;
  }

  LWLockAcquire(pgaudit_ltf_shm->lock, LW_EXCLUSIVE);
  memset(pgaudit_ltf_shm->filename, 0, sizeof(pgaudit_ltf_shm->filename));
  snprintf(pgaudit_ltf_shm->filename, MAXPGPATH, "%s/", guc_pgaudit_ltf_log_directory);
  len = strlen(pgaudit_ltf_shm->filename);
  pg_strftime(pgaudit_ltf_shm->filename + len, MAXPGPATH - len, guc_pgaudit_ltf_log_filename, &tm);
  LWLockRelease(pgaudit_ltf_shm->lock);
}

/*
 * Calculates next rotation time
 */
void PgAuditLogToFile_calculate_next_rotation_time(void)
{
  Timestamp next_rotation_time;

  if (UsedShmemSegAddr == NULL || pgaudit_ltf_shm == NULL)
    return;

  next_rotation_time = pgauditlogtofile_truncate_timestamp(GetCurrentTimestamp());
  next_rotation_time += guc_pgaudit_ltf_log_rotation_age * USECS_PER_MINUTE;

  LWLockAcquire(pgaudit_ltf_shm->lock, LW_EXCLUSIVE);
  pgaudit_ltf_shm->next_rotation_time = next_rotation_time;
  LWLockRelease(pgaudit_ltf_shm->lock);
  ereport(DEBUG3, (errmsg("pgauditlogtofile next_rotation_time %ld %s",
                          pgaudit_ltf_shm->next_rotation_time, timestamptz_to_str(pgaudit_ltf_shm->next_rotation_time))));
}

/*
 * Checks if the audit log file needs to be rotated before we use it
 */
bool PgAuditLogToFile_needs_rotate_file(void)
{
  if (UsedShmemSegAddr == NULL || pgaudit_ltf_shm == NULL)
    return false;

  ereport(DEBUG5, (errmsg("pgauditlogtofile needs_rotate_file %ld %ld", GetCurrentTimestamp(), pgaudit_ltf_shm->next_rotation_time)));
  if (guc_pgaudit_ltf_log_rotation_age > 0 &&
      pgauditlogtofile_truncate_timestamp(GetCurrentTimestamp()) >= pgaudit_ltf_shm->next_rotation_time)
  {
    return true;
  }

  return false;
}

Timestamp
pgauditlogtofile_truncate_timestamp(Timestamp t)
{
  struct pg_tm tm;
  fsec_t fsec;
  Timestamp nt;

  if (timestamp2tm(t, NULL, &tm, &fsec, NULL, NULL) != 0)
  {
    ereport(WARNING, errmsg("pgauditlogtofile failed to truncate timestamp - tm conversion"));
    return t;
  }

  // Discard current seconds
  tm.tm_sec = 0;

  // If we rotate every hour, consider 00 as the current minute
  if (guc_pgaudit_ltf_log_rotation_age >= MINS_PER_HOUR)
  {
    ereport(DEBUG5, errmsg("pgauditlogtofile truncate timestamp - tm_min = 0"));
    tm.tm_min = 0;
  }

  // If we rotate every day, consider 00:00 as the current time
  if (guc_pgaudit_ltf_log_rotation_age >= HOURS_PER_DAY * MINS_PER_HOUR)
  {
    ereport(DEBUG5, errmsg("pgauditlogtofile truncate timestamp - tm_hour = 0"));
    tm.tm_hour = 0;
  }

  if (tm2timestamp(&tm, 0, NULL, &nt) != 0)
  {
    ereport(WARNING, errmsg("pgauditlogtofile failed to truncate timestamp - timestamp conversion"));
    return t;
  }

  return nt;
}