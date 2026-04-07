/*-------------------------------------------------------------------------
 *
 * logtofile_bgw.c
 *      Background worker for logtofile
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_bgw.h"

/* these are always necessary for a bgworker */
#include <miscadmin.h>
#include <postmaster/bgworker.h>
#include <postmaster/interrupt.h>
#include <storage/ipc.h>
#include <storage/latch.h>
#include <storage/lwlock.h>
#include <storage/proc.h>
#include <storage/procarray.h>
#include <storage/shm_mq.h>
#include <storage/shm_toc.h>
#include <storage/shmem.h>
#include <storage/procsignal.h>
#include <utils/backend_status.h>
#include <utils/wait_event.h>
#include <utils/guc.h>
#include <utils/memutils.h>
#include <utils/timestamp.h>

#include "logtofile_filename.h"
#include "logtofile_shmem.h"
#include "logtofile_vars.h"

/*
 * Wait events for pg_stat_activity visibility.
 */
static uint32 pgaudit_wait_main = 0;
static uint32 pgaudit_wait_signal = 0;
static uint32 pgaudit_wait_config = 0;
static uint32 pgaudit_wait_rotate = 0;

/* global settings */

/* flags set by signal handlers */
static volatile sig_atomic_t got_sigterm = false;
static volatile sig_atomic_t got_sigusr1 = false;

/* forward declaration private functions */
static void pgauditlogtofile_sigterm(SIGNAL_ARGS);
static void pgauditlogtofile_sigusr1(SIGNAL_ARGS);
static void pgauditlogtofile_rotate_file(uint32 wait_event_info);

/**
 * @brief Main entry point for the background worker
 * @param arg: unused
 * @return void
 */
void PgAuditLogToFileMain(Datum arg)
{
  int sleep_ms = SECS_PER_MINUTE * 1000;
  MemoryContext PgAuditLogToFileContext = NULL;

  /* Register custom wait events for visibility in pg_stat_activity */
  if (pgaudit_wait_main == 0)
  {
#if (PG_VERSION_NUM >= 170000)
    pgaudit_wait_main = WaitEventExtensionNew("PgAuditLogToFileMain");
    pgaudit_wait_signal = WaitEventExtensionNew("PgAuditLogToFileSignal");
    pgaudit_wait_config = WaitEventExtensionNew("PgAuditLogToFileConfig");
    pgaudit_wait_rotate = WaitEventExtensionNew("PgAuditLogToFileRotate");
#else
    /* custom wait events for extensions were still not available */
    pgaudit_wait_main = PG_WAIT_EXTENSION;
    pgaudit_wait_signal = PG_WAIT_EXTENSION;
    pgaudit_wait_config = PG_WAIT_EXTENSION;
    pgaudit_wait_rotate = PG_WAIT_EXTENSION;
#endif
  }

  pqsignal(SIGHUP, SignalHandlerForConfigReload);
  pqsignal(SIGINT, SIG_IGN);
  pqsignal(SIGTERM, pgauditlogtofile_sigterm);
  pqsignal(SIGUSR1, pgauditlogtofile_sigusr1);

  BackgroundWorkerUnblockSignals();

  pgstat_report_appname("pgauditlogtofile launcher");

  PgAuditLogToFileContext = AllocSetContextCreate(pgaudit_ltf_memory_context, "pgauditlogtofile loop context",
                                                  ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);

  ereport(LOG_SERVER_ONLY, (errmsg("pgauditlogtofile worker started")));

  MemoryContextSwitchTo(PgAuditLogToFileContext);

  while (1)
  {
    int rc;

    CHECK_FOR_INTERRUPTS();

    /* Propagate SIGUSR1 from the bwg to all backends to force an audit file descriptor closure */
    if (got_sigusr1)
    {
      int i;
      PGPROC *proc;

      got_sigusr1 = false;
      pgstat_report_wait_start(pgaudit_wait_signal);

      ereport(LOG, (errmsg("pgauditlogtofile bgw: received SIGUSR1, propagating to backends")));

      /*
       * Acquire a shared lock on the ProcArray to safely iterate
       * through active backends.
       */
      LWLockAcquire(ProcArrayLock, LW_SHARED);

      for (i = 0; i < ProcGlobal->allProcCount; i++)
      {
        proc = &ProcGlobal->allProcs[i];

        /* Don't signal yourself (the background worker) */
        if (proc->pid != MyProcPid && proc->pid != 0)
        {
          /* Send the actual signal via the OS */
          kill(proc->pid, SIGUSR1);
        }
      }

      LWLockRelease(ProcArrayLock);
      pgstat_report_wait_end();
    }

    if (guc_pgaudit_ltf_log_rotation_age > 0 && guc_pgaudit_ltf_log_rotation_age < 5)
    {
      // very small rotation, wake up frequently - this has a performance impact,
      // but rotation every a few minutes should only be done for testing
      sleep_ms = 10000;
    }
    else
    {
      sleep_ms = SECS_PER_MINUTE * 1000;
    }

    ereport(DEBUG5, (errmsg("pgauditlogtofile bgw loop")));
    if (ConfigReloadPending)
    {
      ConfigReloadPending = false;
      ereport(DEBUG3, (errmsg("pgauditlogtofile bgw loop reload cfg")));
      ProcessConfigFile(PGC_SIGHUP);
      pgauditlogtofile_rotate_file(pgaudit_wait_config);
    }
    else if (PgAuditLogToFile_needs_rotate_file())
    {
      ereport(DEBUG3, (errmsg("pgauditlogtofile bgw loop needs rotation %s", pgaudit_ltf_shm->filename)));
      pgauditlogtofile_rotate_file(pgaudit_wait_rotate);
    }

    /* shutdown if requested */
    if (got_sigterm)
      break;

    rc = WaitLatch(&MyProc->procLatch, WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH, sleep_ms,
                   pgaudit_wait_main);
    if (rc & WL_POSTMASTER_DEATH)
      proc_exit(1);

    ResetLatch(&MyProc->procLatch);
    MemoryContextReset(PgAuditLogToFileContext);
  }

  ereport(LOG_SERVER_ONLY, (errmsg("pgauditlogtofile worker shutting down")));

  proc_exit(0);
}

/* private functions */

/**
 * @brief Signal handler for SIGUSR1
 * @param signal_arg: signal number
 * @return void
 */
static void
pgauditlogtofile_sigusr1(SIGNAL_ARGS)
{
  int save_errno = errno;
  got_sigusr1 = true;
  if (MyProc)
    SetLatch(&MyProc->procLatch);

  /* call standard handler to process other interrupts that are reusing the same signal */
  procsignal_sigusr1_handler(postgres_signal_arg);

  errno = save_errno;
}

/**
 * @brief Signal handler for SIGHUP
 * @param signal_arg: signal number
 * @return void
 */
static void
pgauditlogtofile_sigterm(SIGNAL_ARGS)
{
  int save_errno = errno;
  got_sigterm = true;
  if (MyProc != NULL)
    SetLatch(&MyProc->procLatch);
  errno = save_errno;
}

/**
 * @brief Performs the actual log file rotation and cache advice.
 * @param wait_event_info: wait event to report during rotation
 */
static void
pgauditlogtofile_rotate_file(uint32 wait_event_info)
{
  pgstat_report_wait_start(wait_event_info);

  PgAuditLogToFile_calculate_current_filename();
  PgAuditLogToFile_set_next_rotation_time();

  pgstat_report_wait_end();
}