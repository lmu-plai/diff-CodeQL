/**
 * @name Access to sensitive user path files
 * @description Detect access (FileSystemAccess) to sensitive user path files that use process.env or os.homedir (e.g. to get user path)
 * @Author Fabian Froh
 * @kind path-problem
 * @id js/sensitive-user-path-file-access
 * @security-severity 4.0
 * @package-examples eslint-scope (with payload.js)
 * @tags file access
 *       process.env 
 *       os.homedir
 *       user path
 */


 import javascript
 import DataFlow::PathGraph
 
 class SensitiveUserPathFileAccessConfiguration extends TaintTracking::Configuration {
  SensitiveUserPathFileAccessConfiguration() { this = "SensitiveUserPathFileAccessConfiguration" }
 
   override predicate isSource(DataFlow::Node source) {
    source = DataFlow::globalVarRef("process").getAPropertyRead("env") or source = DataFlow::globalVarRef("os").getAPropertyRead("homedir")
   }
 
   override predicate isSink(DataFlow::Node sink) {
     exists(FileSystemAccess f | sink = f.getAPathArgument()) 
   }
 
   override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
     // Storing the information in an object property
     exists( DataFlow::PropWrite propWrite, string property
           | propWrite.writes(succ, property, pred)
           )
     }
 }
 
 from SensitiveUserPathFileAccessConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "Sensitive user path ($@) is used to access a file ($@).", source.getNode(), source.toString(), sink.getNode(), sink.toString()