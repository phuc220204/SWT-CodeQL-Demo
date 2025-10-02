/**
 * @name Possible path traversal when reading files
 * @description Detects fs.readFile / res.download with unvalidated path construction
 * @kind problem
 * @problem.severity warning
 * @tags security
 */

import javascript

from CallExpr call
where
  (call.getCallee().getName() = "readFile" or call.getCallee().getName() = "download") and
  exists(BinaryExpr b | b = call.getArgument(0) and b.getOperator() = "+")
select call, "File path built dynamically — validate/normalize user input to avoid path traversal."
