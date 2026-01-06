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

#include <access/xact.h>
#include <miscadmin.h>
#include <libpq/libpq-be.h>
#include <storage/proc.h>
#include <tcop/tcopprot.h>
#include <utils/json.h>
#include <utils/ps_status.h>

#include <stdarg.h>

/* forward declaration private functions */

inline static void pgauditlogtofile_append_csv_value(StringInfo buf, const char *value)
    __attribute__((always_inline));
static void pgauditlogtofile_append_csv_fmt(StringInfo buf, const char *fmt, ...)
    __attribute__((format(gnu_printf, 2, 3)));
inline static void pgauditlogtofile_pgaudit_escape(StringInfo buf, char *line)
    __attribute__((always_inline));

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

  formatted_log_time = PgAuditLogToFile_format_now_timestamp_millis();
  pgauditlogtofile_append_csv_value(buf, formatted_log_time);
  pfree(formatted_log_time);
  appendStringInfoCharMacro(buf, ',');

  /* username */
  if (MyProcPort && MyProcPort->user_name)
    pgauditlogtofile_append_csv_value(buf, MyProcPort->user_name);
  appendStringInfoCharMacro(buf, ',');

  /* database name */
  if (MyProcPort && MyProcPort->database_name)
    pgauditlogtofile_append_csv_value(buf, MyProcPort->database_name);
  appendStringInfoCharMacro(buf, ',');

  /* Process id  */
  pgauditlogtofile_append_csv_fmt(buf, "%d", MyProcPid);
  appendStringInfoCharMacro(buf, ',');

  /* Remote host and port */
  if (MyProcPort && MyProcPort->remote_host)
  {
    if (MyProcPort->remote_port && MyProcPort->remote_port[0] != '\0')
      pgauditlogtofile_append_csv_fmt(buf, "%s:%s", MyProcPort->remote_host, MyProcPort->remote_port);
    else
      pgauditlogtofile_append_csv_value(buf, MyProcPort->remote_host);
  }
  appendStringInfoCharMacro(buf, ',');

  /* session id - hex representation of start time . session process id */
  pgauditlogtofile_append_csv_fmt(buf, "%lx.%x", (long)MyStartTime, MyProcPid);
  appendStringInfoCharMacro(buf, ',');

  /* PS display */
  if (MyProcPort)
  {
    const char *psdisp;
    int displen;

    psdisp = get_ps_display(&displen);
    if (psdisp && displen > 0)
      pgauditlogtofile_append_csv_value(buf, psdisp);
  }
  appendStringInfoCharMacro(buf, ',');

  /* Virtual transaction id */
  /* keep VXID format in sync with lockfuncs.c */
#if (PG_VERSION_NUM >= 170000)
  if (MyProc != NULL && MyProc->vxid.procNumber != INVALID_PROC_NUMBER)
    pgauditlogtofile_append_csv_fmt(buf, "%d/%u", MyProc->vxid.procNumber, MyProc->vxid.lxid);
#else
  if (MyProc != NULL && MyProc->backendId != InvalidBackendId)
    pgauditlogtofile_append_csv_fmt(buf, "%d/%u", MyProc->backendId, MyProc->lxid);
#endif
  appendStringInfoCharMacro(buf, ',');

  /* Transaction id */
  pgauditlogtofile_append_csv_fmt(buf, "%u", GetTopTransactionIdIfAny());
  appendStringInfoCharMacro(buf, ',');

  /* SQL state code */
  pgauditlogtofile_append_csv_value(buf, unpack_sql_state(edata->sqlerrcode));
  appendStringInfoCharMacro(buf, ',');

  /* errmessage - PGAUDIT formatted text, +7 exclude "AUDIT: " prefix */
  if (exclude_nchars > 0)
    pgauditlogtofile_pgaudit_escape(buf, edata->message + exclude_nchars);
  else
    pgauditlogtofile_append_csv_value(buf, edata->message);
  appendStringInfoCharMacro(buf, ',');

  /* errdetail or errdetail_log */
  if (edata->detail_log)
    pgauditlogtofile_append_csv_value(buf, edata->detail_log);
  else if (edata->detail)
    pgauditlogtofile_append_csv_value(buf, edata->detail);
  appendStringInfoCharMacro(buf, ',');

  /* errhint */
  if (edata->hint)
    pgauditlogtofile_append_csv_value(buf, edata->hint);
  appendStringInfoCharMacro(buf, ',');

  /* internal query */
  if (edata->internalquery)
    pgauditlogtofile_append_csv_value(buf, edata->internalquery);
  appendStringInfoCharMacro(buf, ',');

  /* if printed internal query, print internal pos too */
  if (edata->internalpos > 0 && edata->internalquery != NULL)
    pgauditlogtofile_append_csv_fmt(buf, "%d", edata->internalpos);
  appendStringInfoCharMacro(buf, ',');

  /* errcontext */
  if (edata->context)
    pgauditlogtofile_append_csv_value(buf, edata->context);
  appendStringInfoCharMacro(buf, ',');

  /* user query --- only reported if not disabled by the caller */
  if (debug_query_string != NULL && !edata->hide_stmt)
    print_stmt = true;
  if (print_stmt)
    pgauditlogtofile_append_csv_value(buf, debug_query_string);
  appendStringInfoCharMacro(buf, ',');
  if (print_stmt && edata->cursorpos > 0)
    pgauditlogtofile_append_csv_fmt(buf, "%d", edata->cursorpos);
  appendStringInfoCharMacro(buf, ',');

  /* file error location */
  if (Log_error_verbosity >= PGERROR_VERBOSE)
  {
    size_t needed = strlen(edata->funcname ?: "") + strlen(edata->filename ?: "") + FORMATTED_NUMLINE_LEN;
    char *msgbuf = palloc(needed);

    if (edata->funcname && edata->filename)
      pg_snprintf(msgbuf, needed, "%s, %s:%d", edata->funcname, edata->filename, edata->lineno);
    else if (edata->filename)
      pg_snprintf(msgbuf, needed, "%s:%d", edata->filename, edata->lineno);
    pgauditlogtofile_append_csv_value(buf, msgbuf);
    pfree(msgbuf);
  }
  appendStringInfoCharMacro(buf, ',');

  /* application name */
  if (application_name)
    pgauditlogtofile_append_csv_value(buf, application_name);

  appendStringInfoCharMacro(buf, '\n');
}

/**
 * @brief Writes a CSV value quoted and escaped.
 * @param buf where to write
 * @param value value
 */
static void
pgauditlogtofile_append_csv_value(StringInfo buf, const char *value)
{
  if (value == NULL)
    return;

  escape_json(buf, value);
}

/**
 * @brief Writes a CSV value quoted and escaped.
 * @param buf where to write
 * @param fmt sprintf like formatting string
 * @param any format parameters
 */
static void
pgauditlogtofile_append_csv_fmt(StringInfo buf, const char *fmt, ...)
{
  StringInfoData formatted_value;
  va_list args;

  if (fmt == NULL)
    return;

  initStringInfo(&formatted_value);

  va_start(args, fmt);
  appendStringInfoVA(&formatted_value, fmt, args);
  va_end(args);

  pgauditlogtofile_append_csv_value(buf, formatted_value.data);

  pfree(formatted_value.data);
}

/**
 * @brief Split and escapes each piece on pgaudit original message and writes it as CSV value.
 * @param buf Where to write
 * @param line original pgaudit message, it's modified in this function
 */
static void
pgauditlogtofile_pgaudit_escape(StringInfo buf, char *line)
{
  char *token;

  // AUDIT_TYPE
  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_csv_value(buf, token);
  appendStringInfoCharMacro(buf, ',');

  // STATEMENT_ID
  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_csv_value(buf, token);
  appendStringInfoCharMacro(buf, ',');

  // SUBSTATEMENT_ID
  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_csv_value(buf, token);
  appendStringInfoCharMacro(buf, ',');

  // CLASS
  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_csv_value(buf, token);
  appendStringInfoCharMacro(buf, ',');

  // COMMAND
  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_csv_value(buf, token);
  appendStringInfoCharMacro(buf, ',');

  // OBJECT_TYPE
  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_csv_value(buf, token);
  appendStringInfoCharMacro(buf, ',');

  // OBJECT_NAME
  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_csv_value(buf, token);
  appendStringInfoCharMacro(buf, ',');

  /*
   * writes as one field the statement and the params, but the statement and parameters
   * can contain comma we cannot split them easily
   * */
  if (line && *line != '\0')
    pgauditlogtofile_append_csv_value(buf, line + (*line == ',' ? 1 : 0));
}
