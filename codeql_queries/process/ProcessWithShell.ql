/**
 * @name System command to open shell
 * @description Detect process (SystemCommandExecution) that opens a Windows or Linux shell.
 * @author Fabian Froh
 * @kind problem
 * @id js/process-with-shell
 * @security-severity 10.0
 * @package-examples kraken-api
 * @tags security
 * shell
 * process
 * backdoor
 */

 import javascript

 from SystemCommandExecution s
 // Or use "/bin/%" for anything in the bin directory
 where s.getACommandArgument().toString().matches(["%/bin/sh%", "$cmd$", "%/bin/bash%", "%/bin/zsh%", "%powershell.exe%"])
 select s, "A system command ($@) tries to open a shell", s, s.toString()