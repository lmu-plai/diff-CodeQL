/**
 * @name Detects any client request
 * @description Detects any client request
 * @author Fabian Froh
 * @kind problem
 * @id js/client-request
 * @security-severity 2.0
 * @package-examples eslint-scope
 * @tags security
 * request
 * http
 */

 import javascript
 import relevantCodeUtils

 from ClientRequest h
 // TODO: make more general to always get hostname/URL of a request
 //select h, "Detected a client request with URL: " + ((ObjectExpr)h.getUrl().getAstNode()).getPropertyByName("hostname").getChildExpr(1).getStringValue()
 select h, "Detected a client request to URL/IP address '" + getHostnameOrIPAddressOfClientRequestAsString(h) + "'."