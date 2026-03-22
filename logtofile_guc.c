/*-------------------------------------------------------------------------
 *
 * logtofile_guc.c
 *      GUC variables for logtofile
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_guc.h"

#include <datatype/timestamp.h>
#include <port.h>

#include "logtofile_shmem.h"
#include "logtofile_vars.h"

/**
 * @brief GUC Callback pgaudit.log_directory check path
 * @param newval: new value
 * @param extra: extra
 * @param source: source
 * @return bool: true if path is valid
 */
bool PgAuditLogToFile_guc_check_directory(char **newval, void **extra, GucSource source)
{
  /*
   * Since canonicalize_path never enlarges the string, we can just modify
   * newval in-place.
   */
  canonicalize_path(*newval);
  return true;
}

/**
 * @brief GUC Callback pgaudit.log_filename check value
 * @param newval: new value
 * @param extra: extra
 * @param source: source
 * @return bool: true if filename is valid
 */
bool PgAuditLogToFile_guc_check_filename(char **newval, void **extra, GucSource source)
{
  size_t len = strlen(*newval);
  if ((len > 3 && strcmp(*newval + len - 3, ".gz") == 0) ||
      (len > 4 && strcmp(*newval + len - 4, ".lz4") == 0) ||
      (len > 4 && strcmp(*newval + len - 4, ".zst") == 0))
  {
    GUC_check_errdetail("Log filename cannot end with compression extension (.gz, .lz4, .zst) as it is automatically added when compression is enabled.");
    return false;
  }
  return true;
}

/**
 * @brief GUC Callback pgaudit.log_file_mode
 * @param void
 * @return const char *: file mode
 */
const char *PgAuditLogToFile_guc_show_file_mode(void)
{
  static char buf[12];

  snprintf(buf, sizeof(buf), "%04o", guc_pgaudit_ltf_log_file_mode);
  return buf;
}