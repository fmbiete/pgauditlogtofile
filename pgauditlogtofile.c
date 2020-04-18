/*-------------------------------------------------------------------------
 *
 * pgauditlogtofile.c
 *      pgaudit addon to redirect audit log lines to an independent file
 *
 * Copyright (c) 2020, Francisco Miguel Biete Banon
 * Copyright (c) 2014, 2ndQuadrant Ltd.
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include "utils/guc.h"

#include "logtofile.h"

PG_MODULE_MAGIC;

/*
 * Module load and unload functions
 */

void _PG_init(void);
void _PG_fini(void);

/*
 * Module Load Callback
 */
void _PG_init(void) {
  pgauditlogtofile_init();

  EmitWarningsOnPlaceholders("pgauditlogtofile");
}

/*
 * Module Unload Callback
 */
void _PG_fini(void) { pgauditlogtofile_fini(); }
