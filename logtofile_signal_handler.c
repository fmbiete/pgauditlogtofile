/*-------------------------------------------------------------------------
 *
 * logtofile_signal_handler.c
 *      Functions to override signal handlers
 *
 * Copyright (c) 2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_signal_handler.h"

#include "logtofile_urgentclose.h"
#include "logtofile_vars.h"

#include <storage/procsignal.h>

#include <errno.h>
#include <signal.h>
#include <unistd.h>

/* public methods */

/**
 * @brief Signal handler for SIGUSR1 in backends
 * @param signal_arg: signal number
 * @return void
 */
void PgAuditLogToFile_SIGUSR1(SIGNAL_ARGS)
{
  int save_errno = errno;

  PgAuditLogToFile_close_file_urgent();

  /* Trigger any additional signal handler, minus ignore and default */
  if (pgaudit_ltf_prev_sigusr1_handler &&
      pgaudit_ltf_prev_sigusr1_handler != SIG_IGN &&
      pgaudit_ltf_prev_sigusr1_handler != SIG_DFL)
    pgaudit_ltf_prev_sigusr1_handler(postgres_signal_arg);

  /* call standard handler to process other interrupts that are reusing the same signal */
  procsignal_sigusr1_handler(postgres_signal_arg);

  errno = save_errno;
}