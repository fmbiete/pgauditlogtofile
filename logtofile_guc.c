/*-------------------------------------------------------------------------
 *
 * logtofile_guc.c
 *      GUC variables for logtofile
 *
 * Copyright (c) 2020-2025, Francisco Miguel Biete Banon
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
bool guc_check_directory(char **newval, void **extra, GucSource source)
{
  /*
   * Since canonicalize_path never enlarges the string, we can just modify
   * newval in-place.
   */
  canonicalize_path(*newval);
  return true;
}

/**
 * @brief GUC Callback pgaudit.log_format check value (csv or json)
 * @param newval: new value
 * @param extra: extra
 * @param source: source
 * @return bool: true if value is csv or json
 */
bool guc_check_log_format(char **newval, void **extra, GucSource source)
{
  char *rawstring;

  rawstring = pstrdup(*newval);

  if (pg_strcasecmp(rawstring, "csv") == 0)
  {
    pfree(rawstring);
    return true;
  }

  if (pg_strcasecmp(rawstring, "json") == 0)
  {
    pfree(rawstring);
    return true;
  }

  pfree(rawstring);
  return false;
}