#ifndef _LOGTOFILE_GUC_H_
#define _LOGTOFILE_GUC_H_

#include <postgres.h>
#include <utils/guc.h>

extern bool guc_check_directory(char **newval, void **extra, GucSource source);

#endif
