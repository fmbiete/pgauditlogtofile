# pgauditlogtofile/Makefile

MODULE_big = pgauditlogtofile
OBJS = pgauditlogtofile.o logtofile.o

EXTENSION = pgauditlogtofile
DATA = pgauditlogtofile--1.0.sql

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
