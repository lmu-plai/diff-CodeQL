/**
 * @name Detects obfuscated require statement
 * @description Detect obfuscation attempt when require is assigned to a variable
 * @author Fabian Froh
 * @kind problem
 * @id js/obfuscated-require-declaration
 * @security-severity 8.0
 * @package-examples flatmap-stream
 * @tags security
 * require
 * obfuscation
 */

import javascript

from VariableDeclarator vd
where vd.getInit().toString() = "require"
select vd, "\"Require\" is assigned to a variable (" + vd.getBindingPattern().toString() + "), which could indicate obfuscation."