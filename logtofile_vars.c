/*-------------------------------------------------------------------------
 *
 * logtofile_vars.c
 *      Global variables for logtofile
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_vars.h"

// Guc
char *guc_pgaudit_ltf_log_directory = NULL;
char *guc_pgaudit_ltf_log_filename = NULL;
int guc_pgaudit_ltf_log_file_mode = 0600;
char *guc_pgaudit_log_last_rotation = NULL;
int guc_pgaudit_ltf_log_rotation_age = HOURS_PER_DAY * MINS_PER_HOUR; // Default: 1 day
bool guc_pgaudit_ltf_log_connections = false;                         // Default: off
bool guc_pgaudit_ltf_log_disconnections = false;                      // Default: off
int guc_pgaudit_ltf_auto_close_minutes = 0;                           // Default: off
int guc_pgaudit_ltf_log_format = PGAUDIT_LTF_FORMAT_CSV;              // Default: csv
bool guc_pgaudit_ltf_log_execution_time = false;                      // Default: off
bool guc_pgaudit_ltf_log_execution_memory = false;                    // Default: off
int guc_pgaudit_ltf_log_compression = PGAUDIT_LTF_COMPRESSION_OFF;    // Default: off
int guc_pgaudit_ltf_log_compression_level = 0;                        // Default: 0 (Library default)

// Audit log file handler
int pgaudit_ltf_file_handler = -1;

// Background auto-close file handler
pg_atomic_flag pgaudit_ltf_autoclose_flag_thread;
pthread_t pgaudit_ltf_autoclose_thread;
pthread_attr_t pgaudit_ltf_autoclose_thread_attr;
TimestampTz pgaudit_ltf_autoclose_active_ts;

// Statement time measurement
instr_time pgaudit_ltf_statement_start_time;
instr_time pgaudit_ltf_statement_end_time;

// Statement memory measurement
Size pgaudit_ltf_statement_memory_start = 0;
Size pgaudit_ltf_statement_memory_end = 0;
Size pgaudit_ltf_statement_memory_peak = 0;

// Hook log
emit_log_hook_type pgaudit_ltf_prev_emit_log_hook = NULL;

// Executor Hook
ExecutorStart_hook_type pgaudit_ltf_prev_ExecutorStart = NULL;
ExecutorRun_hook_type pgaudit_ltf_prev_ExecutorRun = NULL;
ExecutorEnd_hook_type pgaudit_ltf_prev_ExecutorEnd = NULL;

// Signal handlers
pqsigfunc pgaudit_ltf_prev_sigusr1_handler = NULL;

// Shared memory
PgAuditLogToFileShm *pgaudit_ltf_shm = NULL;
pg_atomic_flag pgaudit_ltf_flag_shutdown;

// Shared memory hook
shmem_startup_hook_type pgaudit_ltf_prev_shmem_startup_hook = NULL;
#if (PG_VERSION_NUM >= 150000)
shmem_request_hook_type pgaudit_ltf_prev_shmem_request_hook = NULL;
#endif
