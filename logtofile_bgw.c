#include "logtofile_bgw.h"

#include "logtofile_shmem.h"
#include "logtofile_vars.h"

/* these are always necessary for a bgworker */
#include <miscadmin.h>
#include <postmaster/bgworker.h>
#include <storage/ipc.h>
#include <storage/latch.h>
#include <storage/lwlock.h>
#include <storage/proc.h>
#include <storage/shm_mq.h>
#include <storage/shm_toc.h>
#include <storage/shmem.h>
#if (PG_VERSION_NUM >= 140000)
#include <utils/backend_status.h>
#else
#include <pgstat.h>
#endif
#include <utils/memutils.h>
#include <utils/timestamp.h>
#include <utils/guc.h>

/* global settings */
static bool PgAuditLogToFileReloadConfig = false;

/* flags set by signal handlers */
static volatile sig_atomic_t got_sigterm = false;

/* forward declaration private functions */
static void pgauditlogtofile_sighup(SIGNAL_ARGS);
static void pgauditlogtofile_sigterm(SIGNAL_ARGS);

void PgAuditLogToFileMain(Datum arg)
{
  int sleep_ms = SECS_PER_MINUTE * 1000;
  MemoryContext PgAuditLogToFileContext = NULL;

  pqsignal(SIGHUP, pgauditlogtofile_sighup);
  pqsignal(SIGINT, SIG_IGN);
  pqsignal(SIGTERM, pgauditlogtofile_sigterm);

  BackgroundWorkerUnblockSignals();

  pgstat_report_appname("pgauditlogtofile launcher");

  PgAuditLogToFileContext = AllocSetContextCreate(CurrentMemoryContext, "pgauditlogtofile loop context",
                                                  ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);

  ereport(LOG, (errmsg("pgauditlogtofile worker started")));

  MemoryContextSwitchTo(PgAuditLogToFileContext);

  while (1)
  {
    int rc;

    CHECK_FOR_INTERRUPTS();

    if (guc_pgaudit_ltf_log_rotation_age < MINS_PER_HOUR)
    {
      // very small rotation, wake up frequently - this has a performance impact,
      // but rotation every a few minutes should only be done for testing
      sleep_ms = 10000;
    }
    ereport(DEBUG5, (errmsg("pgauditlogtofile bgw loop")));
    if (PgAuditLogToFileReloadConfig)
    {
      ereport(DEBUG3, (errmsg("pgauditlogtofile bgw loop reload cfg")));
      ProcessConfigFile(PGC_SIGHUP);
      PgAuditLogToFile_calculate_filename();
      PgAuditLogToFile_calculate_next_rotation_time();
      ereport(DEBUG3, (errmsg("pgauditlogtofile bgw loop new filename %s", pgaudit_ltf_shm->filename)));
      PgAuditLogToFileReloadConfig = false;
    }
    else
    {
      if (PgAuditLogToFile_needs_rotate_file())
      {
        ereport(DEBUG3, (errmsg("pgauditlogtofile bgw loop needs rotation %s", pgaudit_ltf_shm->filename)));
        PgAuditLogToFile_calculate_filename();
        PgAuditLogToFile_calculate_next_rotation_time();
        ereport(DEBUG3, (errmsg("pgauditlogtofile bgw loop new filename %s", pgaudit_ltf_shm->filename)));
      }
    }

    /* shutdown if requested */
    if (got_sigterm)
      break;

    rc = WaitLatch(&MyProc->procLatch, WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH, sleep_ms,
                   PG_WAIT_EXTENSION);
    if (rc & WL_POSTMASTER_DEATH)
      proc_exit(1);

    ResetLatch(&MyProc->procLatch);
  }

  MemoryContextReset(PgAuditLogToFileContext);

  ereport(LOG, (errmsg("pgauditlogtofile worker shutting down")));

  proc_exit(0);
}

/* private functions */

static void
pgauditlogtofile_sigterm(SIGNAL_ARGS)
{
  got_sigterm = true;
  if (MyProc != NULL)
  {
    SetLatch(&MyProc->procLatch);
  }
}

static void
pgauditlogtofile_sighup(SIGNAL_ARGS)
{
  PgAuditLogToFileReloadConfig = true;
  if (MyProc != NULL)
  {
    SetLatch(&MyProc->procLatch);
  }
}
