/**
 * @name File data in outbound network request
 * @description Directly sending file data in an outbound network request can indicate unauthorized information disclosure.
 * @Author CodeQL Community
 * @kind path-problem
 * @id js/file-access-to-http
 * @package-examples eslint-scope (with payload)
 * @url https://codeql.github.com/codeql-query-help/javascript/js-file-access-to-http/
 * @tags security
 *       external/cwe/cwe-200
 */

 import javascript
 import semmle.javascript.security.dataflow.FileAccessToHttpQuery
 import DataFlow::PathGraph
 import relevantCodeUtils

 from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "File data ($@) flows to outbound network request ($@).", source.getNode(), getFirstCallExprArgumentAsString(source) , sink.getNode(), getHostnameOrIPAddressOfParentClientRequestAsString(sink)