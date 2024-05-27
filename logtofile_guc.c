#include "logtofile_guc.h"

#include <datatype/timestamp.h>
#include <port.h>

#include "logtofile_shmem.h"
#include "logtofile_vars.h"

/*
 * GUC Callback pgaudit.log_directory check path
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
