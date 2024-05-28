# pgauditlogtofile/Makefile
# EL9
#PG_CFLAGS = -fanalyzer -Wall -Wdiscarded-qualifiers
# EL8
PG_CFLAGS = -Wall -Wdiscarded-qualifiers

MODULE_big = pgauditlogtofile
OBJS = pgauditlogtofile.o logtofile.o logtofile_bgw.o logtofile_connect.o logtofile_guc.o logtofile_log.o logtofile_shmem.o logtofile_autoclose.o logtofile_vars.o

EXTENSION = pgauditlogtofile
DATA = pgauditlogtofile--1.0.sql pgauditlogtofile--1.0--1.2.sql pgauditlogtofile--1.2--1.3.sql pgauditlogtofile--1.3--1.4.sql pgauditlogtofile--1.4--1.5.sql pgauditlogtofile--1.5--1.6.sql
PGFILEDESC = "pgAuditLogToFile - An addon for pgAudit logging extension for PostgreSQL"

PG_LDFLAGS = -lz

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
