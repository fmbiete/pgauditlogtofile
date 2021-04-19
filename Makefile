# pgauditlogtofile/Makefile

MODULE_big = pgauditlogtofile
OBJS = pgauditlogtofile.o logtofile.o

EXTENSION = pgauditlogtofile
DATA = pgauditlogtofile--1.2.sql
PGFILEDESC = "pgAuditLogToFile - An addon for pgAudit logging extension for PostgreSQL"

PG_LDFLAGS = -lz

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
