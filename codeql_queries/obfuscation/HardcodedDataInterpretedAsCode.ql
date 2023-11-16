/**
 * @name Hard-coded data interpreted as code
 * @description Transforming hard-coded data (such as hexadecimal constants) into code
 *              to be executed is a technique often associated with backdoors and should
 *              be avoided.
 * @author Fabian Froh based on CodeQL Community (https://codeql.github.com/codeql-query-help/javascript/js-hardcoded-data-interpreted-as-code/)
 * @kind path-problem
 * @id js/hardcoded-data-interpreted-as-code
 * @security-severity 9.0
 * @package-examples flatmap-stream
 * @url https://codeql.github.com/codeql-query-help/javascript/js-hardcoded-data-interpreted-as-code/
 * @tags security
 *       external/cwe/cwe-506
 */

 import javascript
 import HardcodedDataInterpretedAsCodeQuery
 import DataFlow::PathGraph

  // Import own module
  import relevantCodeUtils
 
 from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink,
   "Hard-coded data ($@) is interpreted as code in require argument ($@)", source.getNode(), source.getNode().getStringValue(), sink.getNode(),  getArgumentAsString(sink.getNode().asExpr())