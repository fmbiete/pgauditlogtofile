#ifndef _LOGTOFILE_AUTOCLOSE_H_
#define _LOGTOFILE_AUTOCLOSE_H_

#include <postgres.h>

extern void *PgAuditLogToFile_autoclose_run(void *arg);

#endif
