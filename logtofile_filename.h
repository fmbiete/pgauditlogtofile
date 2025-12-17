/*-------------------------------------------------------------------------
 *
 * logtofile_filename.c
 *      Functions to calculate the filename of the log file
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_FILENAME_H_
#define _LOGTOFILE_FILENAME_H_

#include "postgres.h"

extern char *PgAuditLogToFile_current_filename(void);
extern void PgAuditLogToFile_set_next_rotation_time(void);

#endif // _LOGTOFILE_FILENAME_H_