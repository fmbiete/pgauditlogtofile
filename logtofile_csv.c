/*-------------------------------------------------------------------------
 *
 * logtofile_csv.c
 *      Functions to create a csv audit record
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_csv.h"

#include "logtofile_string_format.h"
#include "logtofile_vars.h"

#include <access/xact.h>
#include <miscadmin.h>
#include <libpq/libpq-be.h>
#include <storage/proc.h>
#include <tcop/tcopprot.h>
#include <utils/json.h>
#include <utils/ps_status.h>
#include <utils/timestamp.h>

#include <stdarg.h>

/* forward declaration private functions */
static void pgauditlogtofile_pgaudit2csv(StringInfo buf, char *line);

/**
 * @brief Creates a csv audit record
 * @param buf: buffer to write the csv line
 * @param edata: error data
 * @param exclude_nchars: number of characters to exclude from the pgaudit message
 * @return void
 */
void PgAuditLogToFile_csv_audit(StringInfo buf, const ErrorData *edata, int exclude_nchars)
{
  char formatted_log_time[FORMATTED_TS_LEN];
  const char *psdisp;
  int displen;
  instr_time now_instr;
  double total_time;
  instr_time duration;
  Size memory_usage;

  /* timestamp with nanoseconds */
  INSTR_TIME_SET_CURRENT(now_instr);
  PgAuditLogToFile_format_instr_time_nanos(now_instr, formatted_log_time, sizeof(formatted_log_time));
  escape_json(buf, formatted_log_time);
  appendStringInfoCharMacro(buf, ',');

  /* username */
  if (MyProcPort && MyProcPort->user_name)
    escape_json(buf, MyProcPort->user_name);
  appendStringInfoCharMacro(buf, ',');

  /* database name */
  if (MyProcPort && MyProcPort->database_name)
    escape_json(buf, MyProcPort->database_name);
  appendStringInfoCharMacro(buf, ',');

  /* Process id  */
  appendStringInfo(buf, "\"%d\"", MyProcPid);
  appendStringInfoCharMacro(buf, ',');

  /* Remote host and port */
  if (MyProcPort && MyProcPort->remote_host)
  {
    if (MyProcPort->remote_port && MyProcPort->remote_port[0] != '\0')
      appendStringInfo(buf, "\"%s:%s\"", MyProcPort->remote_host, MyProcPort->remote_port);
    else
      escape_json(buf, MyProcPort->remote_host);
  }
  appendStringInfoCharMacro(buf, ',');

  /* session id - hex representation of start time . session process id */
  appendStringInfo(buf, "\"%lx.%x\"", (long)MyStartTime, MyProcPid);
  appendStringInfoCharMacro(buf, ',');

  /* PS display */
  psdisp = get_ps_display(&displen);
  if (psdisp && displen > 0)
  {
    if (exclude_nchars == 0 && strncmp(edata->message, "disconnection", 13) == 0)
      escape_json(buf, "disconnection");
    else if (exclude_nchars == 0 && (strncmp(edata->message, "connection authenticated", 24) == 0 ||
                                     strncmp(edata->message, "connection authorized", 21) == 0))
      escape_json(buf, "authentication");
    else
      escape_json(buf, psdisp);
  }
  appendStringInfoCharMacro(buf, ',');

  /* Virtual transaction id */
#if (PG_VERSION_NUM >= 170000)
  if (MyProc != NULL && MyProc->vxid.procNumber != INVALID_PROC_NUMBER)
    appendStringInfo(buf, "\"%d/%u\"", MyProc->vxid.procNumber, MyProc->vxid.lxid);
#else
  if (MyProc != NULL && MyProc->backendId != InvalidBackendId)
    appendStringInfo(buf, "\"%d/%u\"", MyProc->backendId, MyProc->lxid);
#endif
  appendStringInfoCharMacro(buf, ',');

  /* Transaction id */
  appendStringInfo(buf, "\"%u\"", GetTopTransactionIdIfAny());
  appendStringInfoCharMacro(buf, ',');

  /* SQL state code */
  escape_json(buf, unpack_sql_state(edata->sqlerrcode));
  appendStringInfoCharMacro(buf, ',');

  /* errmessage - PGAUDIT formatted text, +7 exclude "AUDIT: " prefix */
  if (exclude_nchars > 0)
    pgauditlogtofile_pgaudit2csv(buf, edata->message + exclude_nchars);
  else
    escape_json(buf, edata->message);
  appendStringInfoCharMacro(buf, ',');

  /* errdetail or errdetail_log */
  if (edata->detail_log)
    escape_json(buf, edata->detail_log);
  else if (edata->detail)
    escape_json(buf, edata->detail);
  appendStringInfoCharMacro(buf, ',');

  /* errhint */
  if (edata->hint)
    escape_json(buf, edata->hint);
  appendStringInfoCharMacro(buf, ',');

  /* internal query */
  if (edata->internalquery)
    escape_json(buf, edata->internalquery);
  appendStringInfoCharMacro(buf, ',');

  /* if printed internal query, print internal pos too */
  if (edata->internalpos > 0 && edata->internalquery != NULL)
    appendStringInfo(buf, "\"%d\"", edata->internalpos);
  appendStringInfoCharMacro(buf, ',');

  /* errcontext */
  if (edata->context)
    escape_json(buf, edata->context);
  appendStringInfoCharMacro(buf, ',');

  /* user query and cursor position */
  if (debug_query_string != NULL && !edata->hide_stmt)
  {
    escape_json(buf, debug_query_string);
    appendStringInfoCharMacro(buf, ',');
    if (edata->cursorpos > 0)
      appendStringInfo(buf, "\"%d\"", edata->cursorpos);
    appendStringInfoCharMacro(buf, ',');
  }
  else
  {
    appendStringInfo(buf, ",,");
  }

  /* file error location */
  if (Log_error_verbosity >= PGERROR_VERBOSE)
  {
    if (edata->funcname && edata->filename)
      appendStringInfo(buf, "\"%s, %s:%d\"", edata->funcname, edata->filename, edata->lineno);
    else if (edata->filename)
      appendStringInfo(buf, "\"%s:%d\"", edata->filename, edata->lineno);
  }
  appendStringInfoCharMacro(buf, ',');

  /* application name */
  if (application_name)
    escape_json(buf, application_name);
  appendStringInfoCharMacro(buf, ',');

  /* execution time */
  if (guc_pgaudit_ltf_log_execution_time &&
      !INSTR_TIME_IS_ZERO(pgaudit_ltf_statement_start_time) &&
      !INSTR_TIME_IS_ZERO(pgaudit_ltf_statement_end_time))
  {
    /* start time */
    PgAuditLogToFile_format_instr_time_nanos(pgaudit_ltf_statement_start_time, formatted_log_time, sizeof(formatted_log_time));
    escape_json(buf, formatted_log_time);
    appendStringInfoCharMacro(buf, ',');

    /* end time */
    PgAuditLogToFile_format_instr_time_nanos(pgaudit_ltf_statement_end_time, formatted_log_time, sizeof(formatted_log_time));
    escape_json(buf, formatted_log_time);
    appendStringInfoCharMacro(buf, ',');

    /* execution time */
    duration = pgaudit_ltf_statement_end_time;
    INSTR_TIME_SUBTRACT(duration, pgaudit_ltf_statement_start_time);
    total_time = INSTR_TIME_GET_DOUBLE(duration);
    appendStringInfo(buf, "\"%.9f\"", total_time);
    appendStringInfoCharMacro(buf, ',');

    /* Reset timing variables after logging */
    INSTR_TIME_SET_ZERO(pgaudit_ltf_statement_start_time);
    INSTR_TIME_SET_ZERO(pgaudit_ltf_statement_end_time);
  }
  else
  {
    appendStringInfo(buf, ",,,");
  }

  /* memory usage */
  if (guc_pgaudit_ltf_log_execution_memory &&
      pgaudit_ltf_statement_memory_start > 0 &&
      pgaudit_ltf_statement_memory_end > 0)
  {
    memory_usage = pgaudit_ltf_statement_memory_end - pgaudit_ltf_statement_memory_start;
    appendStringInfo(buf, "\"%ld\",\"%ld\",\"%ld\",\"%ld\"",
                     (long)pgaudit_ltf_statement_memory_start,
                     (long)pgaudit_ltf_statement_memory_end,
                     (long)pgaudit_ltf_statement_memory_peak,
                     (long)(memory_usage < 0 ? 0 : memory_usage));

    /* Reset memory variables */
    pgaudit_ltf_statement_memory_start = 0;
    pgaudit_ltf_statement_memory_end = 0;
  }
  else
  {
    appendStringInfo(buf, ",,,");
  }

  appendStringInfoCharMacro(buf, '\n');
}

/* private functions */

/**
 * @brief Split and escapes each piece on pgaudit original message and writes it as CSV value.
 * @param buf Where to write
 * @param line original pgaudit message, it's modified in this function
 */
static void
pgauditlogtofile_pgaudit2csv(StringInfo buf, char *line)
{
  char *token;

  /* 1. AUDIT_TYPE */
  token = strsep(&line, ",");
  if (token)
    escape_json(buf, token);
  appendStringInfoCharMacro(buf, ',');

  /* 2. STATEMENT_ID */
  token = strsep(&line, ",");
  if (token)
    escape_json(buf, token);
  appendStringInfoCharMacro(buf, ',');

  /* 3. SUBSTATEMENT_ID */
  token = strsep(&line, ",");
  if (token)
    escape_json(buf, token);
  appendStringInfoCharMacro(buf, ',');

  /* 4. CLASS */
  token = strsep(&line, ",");
  if (token)
    escape_json(buf, token);
  appendStringInfoCharMacro(buf, ',');

  /* 5. COMMAND */
  token = strsep(&line, ",");
  if (token)
    escape_json(buf, token);
  appendStringInfoCharMacro(buf, ',');

  /* 6. OBJECT_TYPE */
  token = strsep(&line, ",");
  if (token)
    escape_json(buf, token);
  appendStringInfoCharMacro(buf, ',');

  /* 7. OBJECT_NAME */
  token = strsep(&line, ",");
  if (token)
    escape_json(buf, token);
  appendStringInfoCharMacro(buf, ',');

  /* 8. Statement and parameters (the rest of the line) */
  if (line && *line != '\0')
    escape_json(buf, line + (*line == ',' ? 1 : 0));
}
