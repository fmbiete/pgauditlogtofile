/*-------------------------------------------------------------------------
 *
 * logtofile_json.c
 *      Functions to create a json audit record
 *
 * Copyright (c) 2020-2025, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_json.h"

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

static void pgauditlogtofile_pgaudit2json(StringInfo buf, char *message);
static void pgauditlogtofile_append_json_key_value(StringInfo buf, const char *key, const char *value);
static void pgauditlogtofile_append_json_key_fmt(StringInfo buf, const char *key, const char *fmt, ...)
    __attribute__((format(gnu_printf, 3, 4)));

/**
 * @brief Creates a json audit record
 * @param buf: buffer to write the json string
 * @param edata: error data
 * @param exclude_nchars: number of characters to exclude from pgaudit message
 * @return void
 */
void PgAuditLogToFile_json_audit(StringInfo buf, const ErrorData *edata, int exclude_nchars)
{
  char *formatted_log_time;

  /* json record start */
  appendStringInfoString(buf, "{\"log.source\":\"pgauditlogtofile\"");
  pgauditlogtofile_append_json_key_value(buf, "severity", "audit");

  /* timestamp with milliseconds */
  formatted_log_time = PgAuditLogToFile_format_now_timestamp_millis();
  pgauditlogtofile_append_json_key_value(buf, "timestamp", formatted_log_time);
  pfree(formatted_log_time);

  /* username */
  if (MyProcPort && MyProcPort->user_name)
    pgauditlogtofile_append_json_key_value(buf, "db.user", MyProcPort->user_name);

  /* database name */
  if (MyProcPort && MyProcPort->database_name)
    pgauditlogtofile_append_json_key_value(buf, "db.name", MyProcPort->database_name);

  /* Process id  */
  pgauditlogtofile_append_json_key_fmt(buf, "custom.process_id", "%d", MyProcPid);

  /* Remote host and port */
  if (MyProcPort && MyProcPort->remote_host)
  {
    pgauditlogtofile_append_json_key_value(buf, "net.peer.name", MyProcPort->remote_host);
    if (MyProcPort->remote_port && MyProcPort->remote_port[0] != '\0')
      pgauditlogtofile_append_json_key_value(buf, "net.peer.port", MyProcPort->remote_port);
  }

  /* session id - hex representation of start time . session process id */
  pgauditlogtofile_append_json_key_fmt(buf, "custom.session_id", "%lx.%x", (long)MyStartTime, MyProcPid);

  /* PS display */
  if (MyProcPort)
  {
    StringInfoData msgbuf;
    const char *psdisp;
    int displen;

    initStringInfo(&msgbuf);

    psdisp = get_ps_display(&displen);
    appendBinaryStringInfo(&msgbuf, psdisp, displen);

    pgauditlogtofile_append_json_key_value(buf, "custom.command_tag", msgbuf.data);

    pfree(msgbuf.data);
  }

  /* Virtual transaction id */
  /* keep VXID format in sync with lockfuncs.c */
#if (PG_VERSION_NUM >= 170000)
  if (MyProc != NULL && MyProc->vxid.procNumber != INVALID_PROC_NUMBER)
  {
    pgauditlogtofile_append_json_key_fmt(buf, "custom.virtual_transaction_id", "%d/%u", MyProc->vxid.procNumber, MyProc->vxid.lxid);
  }
#else
  if (MyProc != NULL && MyProc->backendId != InvalidBackendId)
  {
    pgauditlogtofile_append_json_key_fmt(buf, "custom.virtual_transaction_id", "%d/%u", MyProc->backendId, MyProc->lxid);
  }
#endif

  /* Transaction id */
  pgauditlogtofile_append_json_key_fmt(buf, "custom.virtual_transaction_id", "%u", GetTopTransactionIdIfAny());

  /* SQL state code */
  pgauditlogtofile_append_json_key_value(buf, "custom.state_code", unpack_sql_state(edata->sqlerrcode));

  /* errmessage - PGAUDIT formatted text, +7 exclude "AUDIT: " prefix */
  if (exclude_nchars > 0)
    pgauditlogtofile_pgaudit2json(buf, edata->message + exclude_nchars);
  else
    pgauditlogtofile_append_json_key_value(buf, "content", edata->message);

  /* errdetail or errdetail_log */
  if (edata->detail_log)
    pgauditlogtofile_append_json_key_value(buf, "custom.detail_log", edata->detail_log);
  else if (edata->detail)
    pgauditlogtofile_append_json_key_value(buf, "custom.detail_log", edata->detail);

  /* errhint */
  if (edata->hint)
    pgauditlogtofile_append_json_key_value(buf, "custom.err_hint", edata->hint);

  /* internal query */
  if (edata->internalquery)
    pgauditlogtofile_append_json_key_value(buf, "custom.internal_query", edata->internalquery);

  /* if printed internal query, print internal pos too */
  if (edata->internalpos > 0 && edata->internalquery != NULL)
  {
    pgauditlogtofile_append_json_key_fmt(buf, "custom.internal_query_pos", "%d", edata->internalpos);
  }

  /* errcontext */
  if (edata->context)
    pgauditlogtofile_append_json_key_value(buf, "custom.context", edata->context);

  /* user query --- only reported if not disabled by the caller */
  if (debug_query_string != NULL && !edata->hide_stmt)
  {
    pgauditlogtofile_append_json_key_value(buf, "custom.debug_query", debug_query_string);
    if (edata->cursorpos > 0)
    {
      pgauditlogtofile_append_json_key_fmt(buf, "custom.cursor_pos", "%d", edata->cursorpos);
    }
  }

  /* file error location */
  if (Log_error_verbosity >= PGERROR_VERBOSE)
  {
    if (edata->filename)
    {
      char buffNum[20];
      sprintf(buffNum, "%d", edata->lineno);

      pgauditlogtofile_append_json_key_value(buf, "custom.source_filename", edata->filename);
      pgauditlogtofile_append_json_key_value(buf, "custom.source_linenum", buffNum);
    }
    if (edata->funcname)
      pgauditlogtofile_append_json_key_value(buf, "custom.source_funcname", edata->funcname);
  }

  /* application name */
  if (application_name)
    pgauditlogtofile_append_json_key_value(buf, "custom.application_name", application_name);

  appendStringInfoCharMacro(buf, '}');
  appendStringInfoCharMacro(buf, '\n');
}

/* private methods */

static void
pgauditlogtofile_pgaudit2json(StringInfo buf, char *line)
{
  char *token;

  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_json_key_value(buf, "custom.audit_type", token);

  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_json_key_value(buf, "custom.statement_id", token);

  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_json_key_value(buf, "custom.substatement_id", token);

  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_json_key_value(buf, "custom.class", token);

  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_json_key_value(buf, "custom.command", token);

  token = strsep(&line, ",");
  if (token)
    pgauditlogtofile_append_json_key_value(buf, "custom.object_name", token);

  if (line)
    pgauditlogtofile_append_json_key_value(buf, "content", line + 1);
}

/*
 * Derived from src/backend/utils/error/jsonlog.c appendJSONKeyValue (private)
 *
 * Append to a StringInfo a comma followed by a JSON key and a value.
 * The key is always escaped.  The value is always escaped.
 */
static void
pgauditlogtofile_append_json_key_value(StringInfo buf, const char *key, const char *value)
{
  if (value == NULL)
    return;

  if (key == NULL)
    return;

  appendStringInfoChar(buf, ',');
  escape_json(buf, key);
  appendStringInfoChar(buf, ':');
  escape_json(buf, value);
}

/**
 * @brief Append to a StringInfo a json key+value pair with quotes.
 * @param buf where to write
 * @param key json attribute key
 * @param fmt sprintf like formatting string
 * @param any format parameters
 */
static void
pgauditlogtofile_append_json_key_fmt(StringInfo buf, const char *key, const char *fmt, ...)
{
  StringInfoData formatted_value;
  va_list args;

  if (fmt == NULL)
    return;

  initStringInfo(&formatted_value);

  va_start(args, fmt);
  appendStringInfoVA(&formatted_value, fmt, args);
  va_end(args);

  pgauditlogtofile_append_json_key_value(buf, key, formatted_value.data);

  pfree(formatted_value.data);
}