/**
 * @name Go Call Graph Extractor
 * @description Extracts all method/function calls for call graph and reachability.
 * @kind table
 * @id go/call-graph-extractor
 */

import go

from CallExpr call, Function caller, Function callee, string calleeRecv
where
  call.getEnclosingFunction() = caller
  and call.getTarget() = callee
  and (
    if callee instanceof Method
    then calleeRecv = callee.(Method).getReceiverType().toString()
    else calleeRecv = ""
  )
select
  caller.getFile().getAbsolutePath() as callerFile,
  caller.getStartLine() as callerLine,
  caller.getName() as callerName,
  callee.getPackage().getPath() as calleePkg,
  calleeRecv as calleeRecv,
  callee.getName() as calleeName,
  call.getFile().getAbsolutePath() as callFile,
  call.getStartLine() as callLine
