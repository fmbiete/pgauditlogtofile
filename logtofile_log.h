#ifndef _LOGTOFILE_LOG_H_
#define _LOGTOFILE_LOG_H_

#include <postgres.h>

/* Hook functions */
extern void PgAuditLogToFile_emit_log(ErrorData *edata);

#endif
