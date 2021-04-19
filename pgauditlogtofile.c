/*-------------------------------------------------------------------------
 *
 * pgauditlogtofile.c
 *      pgaudit addon to redirect audit log lines to an independent file
 *
 * Copyright (c) 2020-2021, Francisco Miguel Biete Banon
 * Copyright (c) 2014, 2ndQuadrant Ltd.
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

#include "logtofile.h"
