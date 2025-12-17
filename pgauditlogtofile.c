/*-------------------------------------------------------------------------
 *
 * pgauditlogtofile.c
 *      pgaudit addon to redirect audit log lines to an independent file
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 * Copyright (c) 2014, 2ndQuadrant Ltd.
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include "utils/guc.h"

#ifdef PG_MODULE_MAGIC_EXT // Added in 18
PG_MODULE_MAGIC_EXT(.name = "pgauditlogtofile", .version = "1.7");
#else
PG_MODULE_MAGIC; // For PostgreSQL versions < 18
#endif

#include "logtofile.h"
