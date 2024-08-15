/*-------------------------------------------------------------------------
 *
 * logtofile_vars.c
 *      Global variables for logtofile
 *
 * Copyright (c) 2020-2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_vars.h"

// Guc
char *guc_pgaudit_ltf_log_directory = NULL;
char *guc_pgaudit_ltf_log_filename = NULL;
char *guc_pgaudit_log_last_rotation = NULL;
int guc_pgaudit_ltf_log_rotation_age = HOURS_PER_DAY * MINS_PER_HOUR; // Default: 1 day
int guc_pgaudit_ltf_log_rotation_size = 0;
bool guc_pgaudit_ltf_log_connections = false;                         // Default: off
bool guc_pgaudit_ltf_log_disconnections = false;                      // Default: off
int guc_pgaudit_ltf_auto_close_minutes = 0;                           // Default: off

// Audit log file handler
FILE *pgaudit_ltf_file_handler = NULL;

// Background auto-close file handler
pg_atomic_flag pgaudit_ltf_autoclose_flag_thread;
pthread_t pgaudit_ltf_autoclose_thread;
pthread_attr_t pgaudit_ltf_autoclose_thread_attr;
TimestampTz pgaudit_ltf_autoclose_active_ts;

// Hook log
emit_log_hook_type prev_emit_log_hook = NULL;

// Shared memory
PgAuditLogToFileShm *pgaudit_ltf_shm = NULL;
pg_atomic_flag pgaudit_ltf_flag_shutdown;

// Shared memory hook
shmem_startup_hook_type prev_shmem_startup_hook = NULL;
#if (PG_VERSION_NUM >= 150000)
shmem_request_hook_type prev_shmem_request_hook = NULL;
#endif
