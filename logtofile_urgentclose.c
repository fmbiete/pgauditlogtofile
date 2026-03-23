/*-------------------------------------------------------------------------
 *
 * logtofile_urgentclose.c
 *      Functions to close the audit file descriptor immediately - async-safe
 *
 * Copyright (c) 2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_urgentclose.h"

#include "logtofile_vars.h"

#include <errno.h>

/* public methods */

/**
 * @brief Close the audit log file immediately (Async-Signal-Safe)
 * @param void
 * @return void
 */
void PgAuditLogToFile_close_file_urgent(void)
{
  /* This function is called from a signal handler. It must be async-signal-safe. */
  if (pgaudit_ltf_file_handler != -1)
  {
    int save_errno = errno;
    /* close() is async-signal-safe */
    close(pgaudit_ltf_file_handler);
    pgaudit_ltf_file_handler = -1;
    errno = save_errno;
  }
}
