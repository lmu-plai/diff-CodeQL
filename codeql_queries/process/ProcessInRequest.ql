/**
 * @name Process in client request
 * @description Detect process (SystemCommandExecution) in a request (ClientRequest) that can indicate a backdoor.
 * @author Fabian Froh
 * @kind problem
 * @id js/process-in-request
 * @security-severity 10.0
 * @package-examples kraken-api
 * @tags security
 * request
 * process
 * backdoor
 */

 import javascript

 // Import own module
 import relevantCodeUtils

 from ClientRequest c, SystemCommandExecution s
 where s.getContainer().getParent() = c.getAstNode()
 select s, "A system command ($@) is used in a client request with URL/IP ($@)", s, s.toString(), c, getHostnameOrIPAddressOfClientRequestAsString(c)