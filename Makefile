# pgauditlogtofile/Makefile
EXTENSION = pgauditlogtofile
MODULE_big = pgauditlogtofile
PGFILEDESC = "pgAuditLogToFile - An addon for pgAudit logging extension for PostgreSQL"

OBJS = pgauditlogtofile.o logtofile.o logtofile_bgw.o logtofile_connect.o logtofile_guc.o logtofile_log.o logtofile_shmem.o logtofile_autoclose.o logtofile_vars.o logtofile_filename.o logtofile_json.o logtofile_csv.o logtofile_string_format.o logtofile_execution_memory.o logtofile_execution_time.o logtofile_execution_hook.o logtofile_urgentclose.o logtofile_signal_handler.o logtofile_errordata.o

# Extension Versioning Logic
ALL_VERSIONS = 1.0 1.2 1.3 1.4 1.5 1.6 1.7 1.8
EXTVERSION   = $(lastword $(ALL_VERSIONS))

# Pass the current version as a macro to the C compiler
PG_CPPFLAGS += -DEXTVERSION=\"$(EXTVERSION)\"

# Generate update paths (e.g., 1.0--1.2 1.2--1.3 ...)
UPGRADE_PAIRS = $(join $(filter-out $(EXTVERSION), $(ALL_VERSIONS)), $(patsubst %,--%, $(filter-out $(firstword $(ALL_VERSIONS)), $(ALL_VERSIONS))))

# Base file for current version plus the upgrade chain
SQL_FILES = $(EXTENSION)--$(EXTVERSION).sql $(patsubst %,$(EXTENSION)--%.sql,$(UPGRADE_PAIRS))
DATA = $(SQL_FILES) pgauditlogtofile.control

REGRESS_OPTS = --inputdir=test --outputdir=test --load-extension=pgaudit --load-extension=pgauditlogtofile --user=postgres
REGRESS = extension_exists guc_defaults audit_file_exists audit_file_content audit_file_mode
#REGRESS = extension_exists guc_defaults audit_file_exists audit_file_content rotation connections execution_data file_mode error_conditions disconnection_rotation_1_setup disconnection_rotation_2_check

GCC_VERSION := $(shell gcc -dumpversion | cut -f1 -d.)

PG_CFLAGS += -Wall -Wdiscarded-qualifiers -lz -llz4 -lzstd
ifeq ($(shell [ $(GCC_VERSION) -ge 10 ] && echo true),true)
PG_CFLAGS += -fanalyzer
endif

# This must come before 'include $(PGXS)
EXTRA_CLEAN += $(DATA)

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)


# Propagate C standard to bitcode compiler (Clang)
# This must come after 'include $(PGXS)' because that's where 'with_llvm' is defined
ifeq ($(with_llvm), yes)
    # We append the flag to BITCODE_CFLAGS so the .bc generation also uses C23
    BITCODE_CFLAGS += $(CSTD_FLAG)
endif

# Rule to dynamically generate dummy sql files
$(SQL_FILES): $(EXTENSION)--%.sql:
	@echo "/* $(EXTENSION)/$@ */" > $@
	@echo "" >> $@
	@VERSION_TO=$$(echo "$@" | sed -E 's/.*--//; s/\.sql//'); \
	if echo "$@" | grep -E -q -- "--.*--"; then \
		echo "-- complain if script is sourced in psql, rather than via ALTER EXTENSION" >> $@; \
		printf '\\echo Use "ALTER EXTENSION $(EXTENSION) UPDATE TO '\''%s'\''" to load this file. \\quit\n' "$$VERSION_TO" >> $@; \
	else \
		echo "-- complain if script is sourced in psql, rather than via CREATE EXTENSION" >> $@; \
		printf '\\echo Use "CREATE EXTENSION $(EXTENSION) VERSION '\''%s'\''" to load this file. \\quit\n' "$(EXTVERSION)" >> $@; \
	fi



# Generate the control file from the template
pgauditlogtofile.control: pgauditlogtofile.control.in
	sed 's/@EXTVERSION@/$(EXTVERSION)/g' $< > $@

all: $(DATA)