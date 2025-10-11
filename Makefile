# pgauditlogtofile/Makefile
MODULE_big = pgauditlogtofile
OBJS = pgauditlogtofile.o logtofile.o logtofile_bgw.o logtofile_connect.o logtofile_guc.o logtofile_log.o logtofile_shmem.o logtofile_autoclose.o logtofile_vars.o logtofile_filename.o logtofile_json.o logtofile_csv.o logtofile_string_format.o

EXTENSION = pgauditlogtofile
DATA = pgauditlogtofile--1.0.sql pgauditlogtofile--1.0--1.2.sql pgauditlogtofile--1.2--1.3.sql pgauditlogtofile--1.3--1.4.sql pgauditlogtofile--1.4--1.5.sql pgauditlogtofile--1.5--1.6.sql pgauditlogtofile--1.6--1.7.sql
PGFILEDESC = "pgAuditLogToFile - An addon for pgAudit logging extension for PostgreSQL"

GCC_VERSION := $(shell gcc -dumpversion | cut -f1 -d.)

ifeq ($(shell [ $(GCC_VERSION) -ge 10 ] && echo true),true)
PG_CFLAGS += -fanalyzer -Wall -Wdiscarded-qualifiers
else
PG_CFLAGS += -Wall -Wdiscarded-qualifiers
endif

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
