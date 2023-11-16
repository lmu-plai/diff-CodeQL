/**
 * @name Hard-coded data flowing to / in a request
 * @description Detect hard-coded data (such as hexadecimal constants) that is flowing to or used in a request
 * @Author Fabian Froh based on CodeQL Community (https://codeql.github.com/codeql-query-help/javascript/js-hardcoded-data-interpreted-as-code/)
 * @kind path-problem
 * @id js/hardcoded-data-in-request
 * @package-examples ???
 * @tags security
 *       hard-coded data
 *       request
 *       obfuscation
 */

 import javascript
 import HardcodedDataInRequestQuery
 import DataFlow::PathGraph

 // Import own module
 import relevantCodeUtils
 
 from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink,
   "Hard-coded data ($@) is used in a request as argument ($@)", source.getNode(), source.getNode().getStringValue(), sink.getNode(), getArgumentAsString(sink.getNode().asExpr())