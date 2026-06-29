/**
 * @name Python Call Graph Extractor
 * @description Extracts all calls for Python call graph and reachability.
 * @kind table
 * @id py/call-graph-extractor
 */

import python

from Call call, Function caller
where
  call.getScope() = caller
select
  caller.getFile().getAbsolutePath() as callerFile,
  caller.getLocation().getStartLine() as callerLine,
  caller.getName() as callerName,
  call.getFunc().toString() as calleeName,
  call.getFile().getAbsolutePath() as callFile,
  call.getLocation().getStartLine() as callLine
