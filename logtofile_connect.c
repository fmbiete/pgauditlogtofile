/*-------------------------------------------------------------------------
 *
 * logtofile_connect.c
 *      Functions to parse connect and disconnect messages
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_connect.h"

/**
 * @brief From a list of messages, optionally translated, get the unique prefixes
 * @param messages: list of messages
 * @param num_messages: number of messages
 * @param num_unique: number of unique prefixes
 * @return char **: list of unique prefixes
 */
char **
PgAuditLogToFile_connect_UniquePrefixes(const char **messages, const size_t num_messages, size_t *num_unique)
{
  char **prefixes;
  size_t i;
  size_t count = 0;

  /* Allocate and zero the array; PostgreSQL's palloc handles OOM via ereport */
  prefixes = (char **) palloc0(num_messages * sizeof(char *));

  for (i = 0; i < num_messages; i++)
  {
    const char *message;
    const char *pct;
    size_t len;
    size_t j;
    bool is_unique = true;

#ifdef ENABLE_NLS
    message = gettext(messages[i]);
#else
    message = messages[i];
#endif

    /* Find the first % to determine the prefix length */
    pct = strchr(message, '%');
    len = pct ? (size_t) (pct - message) : strlen(message);

    /* Search only within the unique prefixes found so far (packed) */
    for (j = 0; j < count; j++)
    {
      if (strncmp(prefixes[j], message, len) == 0 && prefixes[j][len] == '\0')
      {
        is_unique = false;
        break;
      }
    }

    if (is_unique)
      prefixes[count++] = pnstrdup(message, len);
  }

  *num_unique = count;
  return prefixes;
}
