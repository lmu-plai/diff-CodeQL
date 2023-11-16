/**
 * @name Detects system command executions
 * @description Detects any SystemCommandExecution
 * @author Fabian Froh
 * @kind problem
 * @id js/system-command-execution
 * @security-severity 2.0
 * @example-packages kraken-api
 * @tags security
 * SystemCommandExecution
 * process
 * spwan
 * exec
 */

 import javascript

 from SystemCommandExecution s
 select s, "Detected SystemCommandExecution (" + s.toString() + ")" 