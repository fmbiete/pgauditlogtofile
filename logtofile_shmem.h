#ifndef _LOGTOFILE_SHMEM_H_
#define _LOGTOFILE_SHMEM_H_

#include <postgres.h>

/* Hook functions */
extern void PgAuditLogToFile_shmem_startup(void);
extern void PgAuditLogToFile_shmem_shutdown(int code, Datum arg);
#if (PG_VERSION_NUM >= 150000)
extern void PgAuditLogToFile_shmem_request(void);
#endif

extern void PgAuditLogToFile_calculate_filename(void);
extern void PgAuditLogToFile_calculate_next_rotation_time(void);
extern bool PgAuditLogToFile_needs_rotate_file(void);

#endif
