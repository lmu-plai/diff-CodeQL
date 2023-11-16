/**
 * @name Detect minified code lines
 * @description Detects lines (StmtContainter) that seem to be minified for obfuscation using a heuristic
 * @author Fabian Froh based on work from Matías Gobbi
 * @kind problem
 * @id js/has-minified-statement-container-code
 * @security-severity 2.0
 * @package-examples pm-controls
 * @tags security
 *       obfuscator
 *       minificator
 */

import javascript


from StmtContainer s, int c
where c = count(Stmt stmt | s = stmt.getContainer())
// Heuristic to detect minified code lines
and c > 5 * s.getNumLines()
and not s.getTopLevel().isMinified()
select s, "Potentially minified code ($@) with " + c + " statements in " + s.getNumLines() + " line", s, s.toString()