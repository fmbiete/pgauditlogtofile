/*-------------------------------------------------------------------------
 *
 * logtofile.h
 *      pgaudit addon to redirect audit log lines to an independent file
 *
 * Copyright (c) 2020, Francisco Miguel Biete Banon
 * Copyright (c) 2014, 2ndQuadrant Ltd.
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef PGAUDITLOGTOFILE_H
#define PGAUDITLOGTOFILE_H

/* initialization functions */
extern void pgauditlogtofile_init(void);
extern void pgauditlogtofile_fini(void);

#endif
