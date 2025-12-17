/*-------------------------------------------------------------------------
 *
 * logtofile_guc.h
 *      GUC variables for logtofile
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_GUC_H_
#define _LOGTOFILE_GUC_H_

#include <postgres.h>
#include <utils/guc.h>

extern bool guc_check_directory(char **newval, void **extra, GucSource source);
extern bool guc_check_log_format(char **newval, void **extra, GucSource source);

#endif
