/*-------------------------------------------------------------------------
 *
 * logtofile_errordata.c
 *      Functions to work with ErrorData struct
 *
 * Copyright (c) 2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_errordata.h"

#include "logtofile_vars.h"

#include <utils/memutils.h>

/**
 * @brief Copy ErrorData object [derived of CopyErrorData]
 * @param edata ErrorData object to duplicate
 */
void PgAuditLogToFile_CopyPendingErrorData(ErrorData *edata)
{
  MemoryContext oldcontext;

  /* Switch to TopMemoryContext so the allocated memory persists across hooks */
  oldcontext = MemoryContextSwitchTo(TopMemoryContext);

  /* Free any previous entry to avoid leaks in TopMemoryContext */
  if (pgaudit_ltf_pending_audit.edata != NULL)
    PgAuditLogToFile_FreePendingErrorData();

  pgaudit_ltf_pending_audit.edata = palloc_object(ErrorData);
  memcpy(pgaudit_ltf_pending_audit.edata, edata, sizeof(ErrorData));

  /*
   * Make copies of separately-allocated strings.  Note that we copy even
   * theoretically-constant strings such as filename.  This is because those
   * could point into JIT-created code segments that might get unloaded at
   * transaction cleanup.  In some cases we need the copied ErrorData to
   * survive transaction boundaries, so we'd better copy those strings too.
   */
  if (edata->filename)
    pgaudit_ltf_pending_audit.edata->filename = pstrdup(edata->filename);
  if (edata->funcname)
    pgaudit_ltf_pending_audit.edata->funcname = pstrdup(edata->funcname);
  if (edata->domain)
    pgaudit_ltf_pending_audit.edata->domain = pstrdup(edata->domain);
  if (edata->context_domain)
    pgaudit_ltf_pending_audit.edata->context_domain = pstrdup(edata->context_domain);
  if (edata->message)
    pgaudit_ltf_pending_audit.edata->message = pstrdup(edata->message);
  if (edata->detail)
    pgaudit_ltf_pending_audit.edata->detail = pstrdup(edata->detail);
  if (edata->detail_log)
    pgaudit_ltf_pending_audit.edata->detail_log = pstrdup(edata->detail_log);
  if (edata->hint)
    pgaudit_ltf_pending_audit.edata->hint = pstrdup(edata->hint);
  if (edata->context)
    pgaudit_ltf_pending_audit.edata->context = pstrdup(edata->context);
  if (edata->backtrace)
    pgaudit_ltf_pending_audit.edata->backtrace = pstrdup(edata->backtrace);
  if (edata->message_id)
    pgaudit_ltf_pending_audit.edata->message_id = pstrdup(edata->message_id);
  if (edata->schema_name)
    pgaudit_ltf_pending_audit.edata->schema_name = pstrdup(edata->schema_name);
  if (edata->table_name)
    pgaudit_ltf_pending_audit.edata->table_name = pstrdup(edata->table_name);
  if (edata->column_name)
    pgaudit_ltf_pending_audit.edata->column_name = pstrdup(edata->column_name);
  if (edata->datatype_name)
    pgaudit_ltf_pending_audit.edata->datatype_name = pstrdup(edata->datatype_name);
  if (edata->constraint_name)
    pgaudit_ltf_pending_audit.edata->constraint_name = pstrdup(edata->constraint_name);
  if (edata->internalquery)
    pgaudit_ltf_pending_audit.edata->internalquery = pstrdup(edata->internalquery);

  /* Ensure assoc_context points to where we actually put it */
  pgaudit_ltf_pending_audit.edata->assoc_context = TopMemoryContext;

  MemoryContextSwitchTo(oldcontext);

  /* mark the record as pending */
  pgaudit_ltf_pending_audit.active = true;
}

/**
 * @brief Free ErrorData object [calls FreeErrorData]
 * @return void
 */
void PgAuditLogToFile_FreePendingErrorData(void)
{
  pgaudit_ltf_pending_audit.active = false;
  if (pgaudit_ltf_pending_audit.edata != NULL)
  {
    FreeErrorData(pgaudit_ltf_pending_audit.edata);
    pgaudit_ltf_pending_audit.edata = NULL;
  }
}