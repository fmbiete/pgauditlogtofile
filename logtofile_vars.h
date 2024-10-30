/*-------------------------------------------------------------------------
 *
 * logtofile_vars.h
 *      Global variables for logtofile
 *
 * Copyright (c) 2020-2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_VARS_H_
#define _LOGTOFILE_VARS_H_

#include <postgres.h>
#include <datatype/timestamp.h>
#include <miscadmin.h>
#include <pgtime.h>
#include <port/atomics.h>
#include <storage/ipc.h>
#include <storage/lwlock.h>
#include <storage/latch.h>

#include <pthread.h>

// Guc
extern char *guc_pgaudit_ltf_log_directory;
extern char *guc_pgaudit_ltf_log_filename;
extern int guc_pgaudit_ltf_log_rotation_age;
extern int guc_pgaudit_ltf_log_rotation_size;
extern bool guc_pgaudit_ltf_log_connections;
extern bool guc_pgaudit_ltf_log_disconnections;
extern int guc_pgaudit_ltf_auto_close_minutes;

// Audit log file handler
extern FILE *pgaudit_ltf_file_handler;

// Background auto-close file handler
extern pg_atomic_flag pgaudit_ltf_autoclose_flag_thread;
extern pthread_t pgaudit_ltf_autoclose_thread;
extern pthread_attr_t pgaudit_ltf_autoclose_thread_attr;
extern Timestamp pgaudit_ltf_autoclose_active_ts;

// Hook log
extern emit_log_hook_type prev_emit_log_hook;

// Shared Memory types
typedef struct PgAuditLogToFilePrefix
{
  char *prefix;
  int length;
} PgAuditLogToFilePrefix;

typedef struct pgAuditLogToFileShm
{
  LWLock *lock;
  PgAuditLogToFilePrefix **prefixes_connection;
  size_t num_prefixes_connection;
  PgAuditLogToFilePrefix **prefixes_disconnection;
  size_t num_prefixes_disconnection;
  char filename[MAXPGPATH];
  pg_time_t next_rotation_time;
  int total_written_bytes;
  bool size_rotation_flag;
  Latch *worker_latch;
} PgAuditLogToFileShm;

// Shared Memory
extern PgAuditLogToFileShm *pgaudit_ltf_shm;
extern pg_atomic_flag pgaudit_ltf_flag_shutdown;

// Shared Memory - Hook
extern shmem_startup_hook_type prev_shmem_startup_hook;
#if (PG_VERSION_NUM >= 150000)
extern shmem_request_hook_type prev_shmem_request_hook;
#endif

#endif
