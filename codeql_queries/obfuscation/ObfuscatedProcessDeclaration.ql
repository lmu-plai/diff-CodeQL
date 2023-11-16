/**
 * @name Detects obfuscated process statement
 * @description Detect obfuscation attempt when process is assigned to a variable
 * @author Fabian Froh
 * @kind problem
 * @id js/obfuscated-process-declaration
 * @security-severity 10.0
 * @package-examples flatmap-stream
 * @tags security
 * process
 * obfuscation
 */

 import javascript

 from VariableDeclarator vd
 where vd.getInit().toString() = "process"
 select vd, "\"process\" object is assigned to a variable (" + vd.getBindingPattern().toString() + "), which could indicate obfuscation."