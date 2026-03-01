#include "logtofile_execution_memory.h"

#include "logtofile_vars.h"

#include <utils/memutils.h>

inline Size MemoryContextTotalAllocated(MemoryContext ctx) __attribute__((always_inline));
inline MemoryContext get_query_memory_context(QueryDesc *queryDesc) __attribute__((always_inline));
inline void update_peak_memory(Size current) __attribute__((always_inline));

/**
 * @brief ExecutorStart hook to record the memory usage at the start of a statement.
 * @param queryDesc
 * @param eflags
 */
void PgAuditLogToFile_ExecutorStart_Memory(QueryDesc *queryDesc, __attribute__((unused)) int eflags)
{
  MemoryContext ctx = get_query_memory_context(queryDesc);

  pgaudit_ltf_statement_memory_start = MemoryContextTotalAllocated(ctx);
  pgaudit_ltf_statement_memory_peak = pgaudit_ltf_statement_memory_start;
  pgaudit_ltf_statement_memory_end = 0;
}

/**
 * @brief ExecutorEnd hook to calculate and log the statement memory usage.
 * @param queryDesc
 */
void PgAuditLogToFile_ExecutorEnd_Memory(QueryDesc *queryDesc)
{
  MemoryContext ctx = get_query_memory_context(queryDesc);

  pgaudit_ltf_statement_memory_end = MemoryContextTotalAllocated(ctx);
  update_peak_memory(pgaudit_ltf_statement_memory_end);
}

/**
 * @brief ExecutorRun hook to capture peak of memory usage during run
 * @param queryDesc
 */
void PgAuditLogToFile_ExecutorRun_Memory(QueryDesc *queryDesc,
                                         __attribute__((unused)) ScanDirection direction,
                                         __attribute__((unused)) uint64 count,
                                         __attribute__((unused)) bool execute_once)
{
  MemoryContext ctx = get_query_memory_context(queryDesc);
  Size current = MemoryContextTotalAllocated(ctx);

  update_peak_memory(current);
}

/**
 * @brief Obtains memory allocated
 * @param ctx
 * @return Size
 */
Size MemoryContextTotalAllocated(MemoryContext ctx)
{
  if (ctx == NULL)
    return 0;

  return MemoryContextMemAllocated(ctx, true);
}

/**
 * @brief Obtains the query context
 * @param queryDesc
 * @return MemoryContext
 */
MemoryContext get_query_memory_context(QueryDesc *queryDesc)
{
  return (queryDesc && queryDesc->estate) ? queryDesc->estate->es_query_cxt : NULL;
}

/**
 * @brief Update the peak memory value if required
 * @param current
 */
void update_peak_memory(Size current)
{
  if (current > pgaudit_ltf_statement_memory_peak)
    pgaudit_ltf_statement_memory_peak = current;
}
