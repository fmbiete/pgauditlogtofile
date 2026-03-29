/*-------------------------------------------------------------------------
 *
 * logtofile_json.c
 *      Functions to create a json audit record
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_json.h"

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

inline static void pgauditlogtofile_pgaudit2json(StringInfo buf, char *message)
    __attribute__((always_inline));

/**
 * @brief Creates a json audit record
 * @param buf: buffer to write the json string
 * @param edata: error data
 * @param exclude_nchars: number of characters to exclude from pgaudit message
 * @return void
 */
void PgAuditLogToFile_json_audit(StringInfo buf, const ErrorData *edata, int exclude_nchars)
{
  char formatted_log_time[FORMATTED_TS_LEN];
  instr_time now_instr;
  const char *psdisp;
  int displen;
  double total_time;
  instr_time duration;
  Size memory_usage;

  /* json record start */
  appendStringInfoString(buf, "{\"log.source\":\"pgauditlogtofile\"");
  appendStringInfoString(buf, ",\"severity\":\"audit\"");

  /* timestamp with nanoseconds */
  INSTR_TIME_SET_CURRENT(now_instr);
  PgAuditLogToFile_format_instr_time_nanos(now_instr, formatted_log_time, sizeof(formatted_log_time));
  appendStringInfoString(buf, ",\"timestamp\":");
  escape_json(buf, formatted_log_time);

  /* username */
  if (MyProcPort && MyProcPort->user_name)
  {
    appendStringInfoString(buf, ",\"db.user\":");
    escape_json(buf, MyProcPort->user_name);
  }

  /* database name */
  if (MyProcPort && MyProcPort->database_name)
  {
    appendStringInfoString(buf, ",\"db.name\":");
    escape_json(buf, MyProcPort->database_name);
  }

  /* Process id  */
  appendStringInfo(buf, ",\"custom.process_id\":\"%d\"", MyProcPid);

  /* Remote host and port */
  if (MyProcPort && MyProcPort->remote_host)
  {
    appendStringInfoString(buf, ",\"net.peer.name\":");
    escape_json(buf, MyProcPort->remote_host);

    if (MyProcPort->remote_port && MyProcPort->remote_port[0] != '\0')
    {
      appendStringInfoString(buf, ",\"net.peer.port\":");
      escape_json(buf, MyProcPort->remote_port);
    }
  }

  /* session id - hex representation of start time . session process id */
  appendStringInfo(buf, ",\"custom.session_id\":\"%lx.%x\"", (long)MyStartTime, MyProcPid);

  /* PS display */
  psdisp = get_ps_display(&displen);
  if (psdisp && displen > 0)
  {
    appendStringInfoString(buf, ",\"custom.command_tag\":");
    if (exclude_nchars == 0 && strncmp(edata->message, "disconnection", 13) == 0)
      escape_json(buf, "disconnection");
    else if (exclude_nchars == 0 && (strncmp(edata->message, "connection authenticated", 24) == 0 ||
                                     strncmp(edata->message, "connection authorized", 21) == 0))
      escape_json(buf, "authentication");
    else
      escape_json(buf, psdisp);
  }

  /* Virtual transaction id */
#if (PG_VERSION_NUM >= 170000)
  if (MyProc != NULL && MyProc->vxid.procNumber != INVALID_PROC_NUMBER)
    appendStringInfo(buf, ",\"custom.virtual_transaction_id\":\"%d/%u\"", MyProc->vxid.procNumber, MyProc->vxid.lxid);
#else
  if (MyProc != NULL && MyProc->backendId != InvalidBackendId)
    appendStringInfo(buf, ",\"custom.virtual_transaction_id\":\"%d/%u\"", MyProc->backendId, MyProc->lxid);
#endif

  /* Transaction id */
  appendStringInfo(buf, ",\"custom.transaction_id\":\"%u\"", GetTopTransactionIdIfAny());

  /* SQL state code */
  appendStringInfoString(buf, ",\"custom.state_code\":");
  escape_json(buf, unpack_sql_state(edata->sqlerrcode));

  /* errmessage - PGAUDIT formatted text, +7 exclude "AUDIT: " prefix */
  if (exclude_nchars > 0)
    pgauditlogtofile_pgaudit2json(buf, edata->message + exclude_nchars);
  else
  {
    appendStringInfoString(buf, ",\"content\":");
    escape_json(buf, edata->message);
  }

  /* errdetail or errdetail_log */
  if (edata->detail_log)
  {
    appendStringInfoString(buf, ",\"custom.detail_log\":");
    escape_json(buf, edata->detail_log);
  }
  else if (edata->detail)
  {
    appendStringInfoString(buf, ",\"custom.detail_log\":");
    escape_json(buf, edata->detail);
  }

  /* errhint */
  if (edata->hint)
  {
    appendStringInfoString(buf, ",\"custom.err_hint\":");
    escape_json(buf, edata->hint);
  }

  /* internal query and position */
  if (edata->internalquery)
  {
    appendStringInfoString(buf, ",\"custom.internal_query\":");
    escape_json(buf, edata->internalquery);
    if (edata->internalpos > 0)
      appendStringInfo(buf, ",\"custom.internal_query_pos\":\"%d\"", edata->internalpos);
  }

  if (edata->context)
  {
    appendStringInfoString(buf, ",\"custom.context\":");
    escape_json(buf, edata->context);
  }

  if (guc_pgaudit_ltf_log_execution_time &&
      !INSTR_TIME_IS_ZERO(pgaudit_ltf_statement_start_time) &&
      !INSTR_TIME_IS_ZERO(pgaudit_ltf_statement_end_time))
  {
    PgAuditLogToFile_format_instr_time_nanos(pgaudit_ltf_statement_start_time, formatted_log_time, sizeof(formatted_log_time));
    appendStringInfoString(buf, ",\"custom.execution_start\":");
    escape_json(buf, formatted_log_time);

    PgAuditLogToFile_format_instr_time_nanos(pgaudit_ltf_statement_end_time, formatted_log_time, sizeof(formatted_log_time));
    appendStringInfoString(buf, ",\"custom.execution_end\":");
    escape_json(buf, formatted_log_time);

    duration = pgaudit_ltf_statement_end_time;
    INSTR_TIME_SUBTRACT(duration, pgaudit_ltf_statement_start_time);
    total_time = INSTR_TIME_GET_DOUBLE(duration);
    appendStringInfo(buf, ",\"custom.execution_time\":\"%.9f\"", total_time);

    INSTR_TIME_SET_ZERO(pgaudit_ltf_statement_start_time);
    INSTR_TIME_SET_ZERO(pgaudit_ltf_statement_end_time);
  }

  if (guc_pgaudit_ltf_log_execution_memory &&
      pgaudit_ltf_statement_memory_start > 0 &&
      pgaudit_ltf_statement_memory_end > 0)
  {
    memory_usage = pgaudit_ltf_statement_memory_end - pgaudit_ltf_statement_memory_start;
    appendStringInfo(buf, ",\"custom.execution_memory.start\":\"%ld\"", (long)pgaudit_ltf_statement_memory_start);
    appendStringInfo(buf, ",\"custom.execution_memory.end\":\"%ld\"", (long)pgaudit_ltf_statement_memory_end);
    appendStringInfo(buf, ",\"custom.execution_memory.peak\":\"%ld\"", (long)pgaudit_ltf_statement_memory_peak);
    appendStringInfo(buf, ",\"custom.execution_memory.delta\":\"%ld\"", (long)(memory_usage < 0 ? 0 : memory_usage));

    pgaudit_ltf_statement_memory_start = 0;
    pgaudit_ltf_statement_memory_end = 0;
  }

  appendStringInfoCharMacro(buf, '}');
  appendStringInfoCharMacro(buf, '\n');
}

/* private functions */

/**
 * @brief Split and escapes each piece on pgaudit original message and writes it as json key/value pair.
 * @param buf Where to write
 * @param line original pgaudit message, it's modified in this function
 */
static void
pgauditlogtofile_pgaudit2json(StringInfo buf, char *line)
{
  char *token;

  // AUDIT_TYPE
  token = strsep(&line, ",");
  if (token)
  {
    appendStringInfoString(buf, ",\"custom.audit_type\":");
    escape_json(buf, token);
  }

  // STATEMENT_ID
  token = strsep(&line, ",");
  if (token)
  {
    appendStringInfoString(buf, ",\"custom.statement_id\":");
    escape_json(buf, token);
  }

  // SUBSTATEMENT_ID
  token = strsep(&line, ",");
  if (token)
  {
    appendStringInfoString(buf, ",\"custom.substatement_id\":");
    escape_json(buf, token);
  }

  // CLASS
  token = strsep(&line, ",");
  if (token)
  {
    appendStringInfoString(buf, ",\"custom.class\":");
    escape_json(buf, token);
  }

  // COMMAND
  token = strsep(&line, ",");
  if (token)
  {
    appendStringInfoString(buf, ",\"custom.command\":");
    escape_json(buf, token);
  }

  // OBJECT_TYPE
  token = strsep(&line, ",");
  if (token)
  {
    appendStringInfoString(buf, ",\"custom.object_type\":");
    escape_json(buf, token);
  }

  // OBJECT_NAME
  token = strsep(&line, ",");
  if (token)
  {
    appendStringInfoString(buf, ",\"custom.object_name\":");
    escape_json(buf, token);
  }

  // Statement and parameters as one field
  if (line && *line != '\0')
  {
    appendStringInfoString(buf, ",\"content\":");
    escape_json(buf, line + (*line == ',' ? 1 : 0));
  }
}
