/**
 * @name Response contains direct user input (possible XSS)
 * @description Finds res.send/res.write that include template strings or identifiers directly from request parameters
 * @kind problem
 * @problem.severity warning
 * @tags security
 */

import javascript

from CallExpr call, TemplateString t
where
  (call.getCallee().getName() = "send" or call.getCallee().getName() = "write") and
  exists(t | t = call.getArgument(0))
select call, "Response contains a template string — ensure output is properly escaped/encoded to prevent XSS."