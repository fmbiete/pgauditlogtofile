/*-------------------------------------------------------------------------
 *
 * logtofile_urgentclose.h
 *      Functions to close the audit file descriptor immediately - async-safe
 *
 * Copyright (c) 2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_URGENTCLOSE_H_
#define _LOGTOFILE_URGENTCLOSE_H_

#include <postgres.h>

/* Async-Safe Signal Handler */
extern void PgAuditLogToFile_close_file_urgent(void);

#endif
