/**
 * @name Use of child_process exec
 * @description Detects calls to exec/execSync/spawn (possible command injection)
 * @kind problem
 * @problem.severity warning
 * @tags security
 */

import javascript

from CallExpr call, string name
where
  (name = call.getCallee().getName() and (name = "exec" or name = "execSync" or name = "spawn"))
select call, "Call to " + name + " — ensure input isn't user-controlled (risk of command injection)."