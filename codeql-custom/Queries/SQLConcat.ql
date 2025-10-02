/**
 * @name SQL query built by concatenation
 * @description Detects db.query(...) where the first argument is a string concatenation or template literal (possible SQL injection)
 * @kind problem
 * @problem.severity warning
 * @tags security
 */

import javascript

from CallExpr call
where
  call.getCallee().getName() = "query" and
  (
    exists(BinaryExpr b | b = call.getArgument(0) and b.getOperator() = "+")
    or
    exists(TemplateString t | t = call.getArgument(0))
  )
select call, "SQL query appears to be constructed via concatenation/template — parameterize queries to avoid SQL injection."