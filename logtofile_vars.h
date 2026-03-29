/*-------------------------------------------------------------------------
 *
 * logtofile_vars.h
 *      Global variables for logtofile
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_VARS_H_
#define _LOGTOFILE_VARS_H_

#include <postgres.h>
#include <datatype/timestamp.h>
#include <executor/executor.h>
#include <miscadmin.h>
#include <pgtime.h>
#include <port/atomics.h>
#include <portability/instr_time.h>
#include <signal.h>
#include <storage/ipc.h>
#include <storage/lwlock.h>
#include <utils/timestamp.h>
#include <utils/elog.h>

#include <pthread.h>

typedef enum
{
  PGAUDIT_LTF_FORMAT_CSV,
  PGAUDIT_LTF_FORMAT_JSON
} PgAuditLogToFileFormat;

typedef enum
{
  PGAUDIT_LTF_COMPRESSION_OFF,
  PGAUDIT_LTF_COMPRESSION_GZIP,
  PGAUDIT_LTF_COMPRESSION_LZ4,
  PGAUDIT_LTF_COMPRESSION_ZSTD
} PgAuditLogToFileCompression;

// Guc
extern char *guc_pgaudit_ltf_log_directory;
extern char *guc_pgaudit_ltf_log_filename;
extern int guc_pgaudit_ltf_log_file_mode;
extern int guc_pgaudit_ltf_log_rotation_age;
extern bool guc_pgaudit_ltf_log_connections;
extern bool guc_pgaudit_ltf_log_disconnections;
extern int guc_pgaudit_ltf_auto_close_minutes;
extern int guc_pgaudit_ltf_log_format;
extern bool guc_pgaudit_ltf_log_execution_time;
extern bool guc_pgaudit_ltf_log_execution_memory;
extern int guc_pgaudit_ltf_log_compression;
extern int guc_pgaudit_ltf_log_compression_level;

// Audit log file handler
extern int pgaudit_ltf_file_handler;

// Background auto-close file handler
extern pg_atomic_flag pgaudit_ltf_autoclose_flag_thread;
extern pthread_t pgaudit_ltf_autoclose_thread;
extern pthread_attr_t pgaudit_ltf_autoclose_thread_attr;
extern Timestamp pgaudit_ltf_autoclose_active_ts;

// Statement time measurement
extern instr_time pgaudit_ltf_statement_start_time;
extern instr_time pgaudit_ltf_statement_end_time;

// Statement memory measurement
extern Size pgaudit_ltf_statement_memory_start;
extern Size pgaudit_ltf_statement_memory_end;
extern Size pgaudit_ltf_statement_memory_peak;

// Pending audit data to capture stats at the end of execution
typedef struct
{
  ErrorData *edata;
  bool active;
} PendingAudit;

extern PendingAudit pgaudit_ltf_pending_audit;

// Hook log
extern emit_log_hook_type pgaudit_ltf_prev_emit_log_hook;

// Executor Hook
extern ExecutorStart_hook_type pgaudit_ltf_prev_ExecutorStart;
extern ExecutorRun_hook_type pgaudit_ltf_prev_ExecutorRun;
extern ExecutorEnd_hook_type pgaudit_ltf_prev_ExecutorEnd;

// Signal handlers
extern pqsigfunc pgaudit_ltf_prev_sigusr1_handler;

// Shared Memory types
typedef enum
{
  PGAUDIT_LTF_TYPE_CONNECTION,
  PGAUDIT_LTF_TYPE_DISCONNECTION
} PgAuditLogToFilePrefixType;

typedef struct PgAuditLogToFilePrefix
{
  int length;
  PgAuditLogToFilePrefixType type;
  char prefix[FLEXIBLE_ARRAY_MEMBER];
} PgAuditLogToFilePrefix;

typedef struct pgAuditLogToFileShm
{
  LWLock lock;
  char filename[MAXPGPATH];
  pg_time_t next_rotation_time;
  pg_atomic_uint32 rotation_generation;
  size_t num_prefixes;
  PgAuditLogToFilePrefix *prefixes[FLEXIBLE_ARRAY_MEMBER];
} PgAuditLogToFileShm;

// Shared Memory
extern PgAuditLogToFileShm *pgaudit_ltf_shm;
extern pg_atomic_flag pgaudit_ltf_flag_shutdown;

// Shared Memory - Hook
extern shmem_startup_hook_type pgaudit_ltf_prev_shmem_startup_hook;
#if (PG_VERSION_NUM >= 150000)
extern shmem_request_hook_type pgaudit_ltf_prev_shmem_request_hook;
#endif

#endif
