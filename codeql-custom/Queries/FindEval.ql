/**
 * @name Use of eval()
 * @description Detects calls to eval()
 * @kind problem
 * @problem.severity warning
 * @tags security
 */

import javascript

from CallExpr call
where call.getCallee().getName() = "eval"
select call, "Avoid using eval()."