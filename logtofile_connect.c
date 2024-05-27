#include "logtofile_connect.h"

char **
PgAuditLogToFile_connect_UniquePrefixes(const char **messages, const size_t num_messages, size_t *num_unique)
{
  bool is_unique;
  char **prefixes = NULL;
  char *prefix, *dup;
#ifdef ENABLE_NLS
  char *message;
#else
  const char *message;
#endif
  size_t i, j;

  *num_unique = 0;

  prefixes = palloc(num_messages * sizeof(char *));
  if (prefixes != NULL) {
    for (i = 0; i < num_messages; i++) {
  #ifdef ENABLE_NLS
      // Get translation - static copy
      message = gettext(messages[i]);
  #else
      // Pointer to original = static copy
      message = messages[i];
  #endif
      // Get a copy that we can modify
      dup = pstrdup(message);
      if (dup != NULL) {
        prefix = strtok(dup, "%");
        if (prefix != NULL) {
          // Search duplicated
          is_unique = true;
          for (j = 0; j < i; j++) {
            if (prefixes[j] != NULL) {
              if (strcmp(prefixes[j], prefix) == 0) {
                // Skip - prefix already present
                is_unique = false;
              }
            }
          }

          if (is_unique) {
            prefixes[i] = palloc((strlen(prefix) + 1) * sizeof(char));
            if (prefixes[i] != NULL) {
              strcpy(prefixes[i], prefix);
              *num_unique += 1;
            }
          } else {
            prefixes[i] = NULL;
          }
        }
        pfree(dup);
      }
    }
  }

  return prefixes;
}
