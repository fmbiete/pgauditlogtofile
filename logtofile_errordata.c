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

/*
 * @brief Copy ErrorData object [derived of CopyErrorData]
 * @param ErrorData object to duplicate
 */
void PgAuditLogToFile_CopyPendingErrorData(ErrorData *edata)
{
  pgaudit_ltf_pending_audit.edata = palloc_object(ErrorData);
  memcpy(pgaudit_ltf_pending_audit.edata, edata, sizeof(ErrorData));

  /*
   * Make copies of separately-allocated strings.  Note that we copy even
   * theoretically-constant strings such as filename.  This is because those
   * could point into JIT-created code segments that might get unloaded at
   * transaction cleanup.  In some cases we need the copied ErrorData to
   * survive transaction boundaries, so we'd better copy those strings too.
   */
  if (pgaudit_ltf_pending_audit.edata->filename)
    pgaudit_ltf_pending_audit.edata->filename = pstrdup(edata->filename);
  if (pgaudit_ltf_pending_audit.edata->funcname)
    pgaudit_ltf_pending_audit.edata->funcname = pstrdup(edata->funcname);
  if (pgaudit_ltf_pending_audit.edata->domain)
    pgaudit_ltf_pending_audit.edata->domain = pstrdup(edata->domain);
  if (pgaudit_ltf_pending_audit.edata->context_domain)
    pgaudit_ltf_pending_audit.edata->context_domain = pstrdup(edata->context_domain);
  if (pgaudit_ltf_pending_audit.edata->message)
    pgaudit_ltf_pending_audit.edata->message = pstrdup(edata->message);
  if (pgaudit_ltf_pending_audit.edata->detail)
    pgaudit_ltf_pending_audit.edata->detail = pstrdup(edata->detail);
  if (pgaudit_ltf_pending_audit.edata->detail_log)
    pgaudit_ltf_pending_audit.edata->detail_log = pstrdup(edata->detail_log);
  if (pgaudit_ltf_pending_audit.edata->hint)
    pgaudit_ltf_pending_audit.edata->hint = pstrdup(edata->hint);
  if (pgaudit_ltf_pending_audit.edata->context)
    pgaudit_ltf_pending_audit.edata->context = pstrdup(edata->context);
  if (pgaudit_ltf_pending_audit.edata->backtrace)
    pgaudit_ltf_pending_audit.edata->backtrace = pstrdup(edata->backtrace);
  if (pgaudit_ltf_pending_audit.edata->message_id)
    pgaudit_ltf_pending_audit.edata->message_id = pstrdup(edata->message_id);
  if (pgaudit_ltf_pending_audit.edata->schema_name)
    pgaudit_ltf_pending_audit.edata->schema_name = pstrdup(edata->schema_name);
  if (pgaudit_ltf_pending_audit.edata->table_name)
    pgaudit_ltf_pending_audit.edata->table_name = pstrdup(edata->table_name);
  if (pgaudit_ltf_pending_audit.edata->column_name)
    pgaudit_ltf_pending_audit.edata->column_name = pstrdup(edata->column_name);
  if (pgaudit_ltf_pending_audit.edata->datatype_name)
    pgaudit_ltf_pending_audit.edata->datatype_name = pstrdup(edata->datatype_name);
  if (pgaudit_ltf_pending_audit.edata->constraint_name)
    pgaudit_ltf_pending_audit.edata->constraint_name = pstrdup(edata->constraint_name);
  if (pgaudit_ltf_pending_audit.edata->internalquery)
    pgaudit_ltf_pending_audit.edata->internalquery = pstrdup(edata->internalquery);

  /* Use the calling context for string allocation */
  pgaudit_ltf_pending_audit.edata->assoc_context = CurrentMemoryContext;

  /* mark the record as pending */
  pgaudit_ltf_pending_audit.active = true;
}

/*
 * @brief Free ErrorData object [derived of FreeErrorData]
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