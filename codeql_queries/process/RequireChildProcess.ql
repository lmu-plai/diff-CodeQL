/**
 * @name Require of child process
 * @description Detects if any child process is required as module
 * @author Fabian Froh
 * @kind problem
 * @id js/require-child-process
 * @security-severity 3.0
 * @example-packages kraken-api
 * @tags security
 * child_process
 * process
 * spwan
 * exec
 */

 import javascript

 from Require r
 where r.getImportedPath().toString() = "'child_process'"
 select r, "Require of child_process module in file \"" + r.getFile().getBaseName().toString() + "\""