/*-------------------------------------------------------------------------
 *
 * logtofile_csv.c
 *      Functions to create a csv audit record
 *
 * Copyright (c) 2020-2025, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_csv.h"

#include "logtofile_string_format.h"

#include <access/xact.h>
#include <miscadmin.h>
#include <lib/stringinfo.h>
#include <libpq/libpq-be.h>
#include <storage/proc.h>
#include <tcop/tcopprot.h>
#include <utils/ps_status.h>

/**
 * @brief Creates a csv audit record
 * @param buf: buffer to write the csv line
 * @param edata: error data
 * @param exclude_nchars: number of characters to exclude from the pgaudit message
 * @return void
 */
void PgAuditLogToFile_csv_audit(StringInfo buf, const ErrorData *edata, int exclude_nchars)
{
  bool print_stmt = false;
  char *formatted_log_time;

  /* timestamp with milliseconds */

  formatted_log_time = PgAuditLogToFile_format_now_timestamp();
  appendStringInfoString(buf, formatted_log_time);
  appendStringInfoCharMacro(buf, ',');
  pfree(formatted_log_time);

  /* username */
  if (MyProcPort && MyProcPort->user_name)
    appendStringInfoString(buf, MyProcPort->user_name);
  appendStringInfoCharMacro(buf, ',');

  /* database name */
  if (MyProcPort && MyProcPort->database_name)
    appendStringInfoString(buf, MyProcPort->database_name);
  appendStringInfoCharMacro(buf, ',');

  /* Process id  */
  appendStringInfo(buf, "%d", MyProcPid);
  appendStringInfoCharMacro(buf, ',');

  /* Remote host and port */
  if (MyProcPort && MyProcPort->remote_host)
  {
    appendStringInfoString(buf, MyProcPort->remote_host);
    if (MyProcPort->remote_port && MyProcPort->remote_port[0] != '\0')
    {
      appendStringInfoCharMacro(buf, ':');
      appendStringInfoString(buf, MyProcPort->remote_port);
    }
  }
  appendStringInfoCharMacro(buf, ',');

  /* session id - hex representation of start time . session process id */
  appendStringInfo(buf, "%lx.%x", (long)MyStartTime, MyProcPid);
  appendStringInfoCharMacro(buf, ',');

  /* PS display */
  if (MyProcPort)
  {
    StringInfoData msgbuf;
    const char *psdisp;
    int displen;

    initStringInfo(&msgbuf);

    psdisp = get_ps_display(&displen);
    appendBinaryStringInfo(&msgbuf, psdisp, displen);
    appendStringInfoString(buf, msgbuf.data);

    pfree(msgbuf.data);
  }
  appendStringInfoCharMacro(buf, ',');

  /* Virtual transaction id */
  /* keep VXID format in sync with lockfuncs.c */
#if (PG_VERSION_NUM >= 170000)
  if (MyProc != NULL && MyProc->vxid.procNumber != INVALID_PROC_NUMBER)
    appendStringInfo(buf, "%d/%u", MyProc->vxid.procNumber, MyProc->vxid.lxid);
#else
  if (MyProc != NULL && MyProc->backendId != InvalidBackendId)
    appendStringInfo(buf, "%d/%u", MyProc->backendId, MyProc->lxid);
#endif
  appendStringInfoCharMacro(buf, ',');

  /* Transaction id */
  appendStringInfo(buf, "%u", GetTopTransactionIdIfAny());
  appendStringInfoCharMacro(buf, ',');

  /* SQL state code */
  appendStringInfoString(buf, unpack_sql_state(edata->sqlerrcode));
  appendStringInfoCharMacro(buf, ',');

  /* errmessage - PGAUDIT formatted text, +7 exclude "AUDIT: " prefix */
  appendStringInfoString(buf, edata->message + exclude_nchars);
  appendStringInfoCharMacro(buf, ',');

  /* errdetail or errdetail_log */
  if (edata->detail_log)
    appendStringInfoString(buf, edata->detail_log);
  else if (edata->detail)
    appendStringInfoString(buf, edata->detail);
  appendStringInfoCharMacro(buf, ',');

  /* errhint */
  if (edata->hint)
    appendStringInfoString(buf, edata->hint);
  appendStringInfoCharMacro(buf, ',');

  /* internal query */
  if (edata->internalquery)
    appendStringInfoString(buf, edata->internalquery);
  appendStringInfoCharMacro(buf, ',');

  /* if printed internal query, print internal pos too */
  if (edata->internalpos > 0 && edata->internalquery != NULL)
    appendStringInfo(buf, "%d", edata->internalpos);
  appendStringInfoCharMacro(buf, ',');

  /* errcontext */
  if (edata->context)
    appendStringInfoString(buf, edata->context);
  appendStringInfoCharMacro(buf, ',');

  /* user query --- only reported if not disabled by the caller */
  if (debug_query_string != NULL && !edata->hide_stmt)
    print_stmt = true;
  if (print_stmt)
    appendStringInfoString(buf, debug_query_string);
  appendStringInfoCharMacro(buf, ',');
  if (print_stmt && edata->cursorpos > 0)
    appendStringInfo(buf, "%d", edata->cursorpos);
  appendStringInfoCharMacro(buf, ',');

  /* file error location */
  if (Log_error_verbosity >= PGERROR_VERBOSE)
  {
    StringInfoData msgbuf;

    initStringInfo(&msgbuf);

    if (edata->funcname && edata->filename)
      appendStringInfo(&msgbuf, "%s, %s:%d", edata->funcname, edata->filename,
                       edata->lineno);
    else if (edata->filename)
      appendStringInfo(&msgbuf, "%s:%d", edata->filename, edata->lineno);
    appendStringInfoString(buf, msgbuf.data);
    pfree(msgbuf.data);
  }
  appendStringInfoCharMacro(buf, ',');

  /* application name */
  if (application_name)
    appendStringInfoString(buf, application_name);

  appendStringInfoCharMacro(buf, '\n');
}