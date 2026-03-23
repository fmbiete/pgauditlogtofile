/*-------------------------------------------------------------------------
 *
 * logtofile_signal_handler.h
 *      Functions to override signal handlers
 *
 * Copyright (c) 2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_SIGNAL_HANDLER_H_
#define _LOGTOFILE_SIGNAL_HANDLER_H_

#include <postgres.h>

extern void PgAuditLogToFile_SIGUSR1(SIGNAL_ARGS);

#endif /* _LOGTOFILE_SIGNAL_HANDLER_H_ */