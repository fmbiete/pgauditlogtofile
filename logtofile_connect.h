#ifndef _LOGTOFILE_CONNECT_H_
#define _LOGTOFILE_CONNECT_H_

#include <postgres.h>

extern char **
PgAuditLogToFile_connect_UniquePrefixes(const char **messages, const size_t num_messages, size_t *num_unique);

#endif
