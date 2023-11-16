/**
 * @name Flow of sensitive file path to request
 * @description Detect data flow from sensitive file with path that includes process.env, os.homedir or os.userInfo to request (ClientRequest)
 * @Author Fabian Froh
 * @kind path-problem
 * @id js/sensitive-file-path-to-request
 * @security-severity 8.0
 * @package-examples eslint-scope (with payload.js)
 * @tags request
 *       sensitive file
 *       process.env 
 *       os.homedir
 */


 import javascript
 import DataFlow::PathGraph
 import relevantCodeUtils
 
 class SensitiveFileToRequestConfiguration extends TaintTracking::Configuration {
  SensitiveFileToRequestConfiguration() { this = "SensitiveFileToRequestConfiguration" }
 
   override predicate isSource(DataFlow::Node source) {
    source = DataFlow::globalVarRef("process").getAPropertyRead("env") or source = DataFlow::globalVarRef("os").getAPropertyRead("homedir") or
    source = DataFlow::globalVarRef("os").getAPropertyRead("userInfo")
   }
 
   override predicate isSink(DataFlow::Node sink) {
     exists(ClientRequest c | sink = c.getAnArgument())
   }
   
   override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Passed as an argument: https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-javascript-and-typescript/#analyzing-data-flow-in-javascript-and-typescript
    exists(DataFlow::CallNode c | pred = c.getAnArgument() and succ = c) or
    // Storing the information in an object property
    exists( DataFlow::PropWrite propWrite, string property
        | propWrite.writes(succ, property, pred)
        )
     }
     
 }
 
 from SensitiveFileToRequestConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "Sensitive file path ($@) flows to a request ($@).", source.getNode(), source.toString(), sink.getNode(), getHostnameOrIPAddressOfParentClientRequestAsString(sink)