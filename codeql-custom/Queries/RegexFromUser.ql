/**
 * @name User-controlled regex (ReDoS risk)
 * @description Detects new RegExp(pattern) where pattern may come from user input
 * @kind problem
 * @problem.severity warning
 * @tags security
 */

import javascript

from NewExpr ne
where ne.getType().getName() = "RegExp" and exists(ne.getArgument(0))
select ne,
  "RegExp constructed dynamically — ensure patterns are not attacker-controlled (risk of ReDoS)."
