/**
 * @name Potential prototype pollution via object merge
 * @description Simple pattern to flag merges from user-controlled objects
 * @kind problem
 * @problem.severity warning
 * @tags security
 */

import javascript

from FunctionCall fc
where fc.getTarget().getName() = "merge" and fc.getArgument(1) instanceof Expr
select fc,
  "Function `merge` called with possibly user-controlled second argument — check for prototype pollution."
