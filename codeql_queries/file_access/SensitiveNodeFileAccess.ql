/**
 * @name Flow from SensitiveNode to FileAccess
 * @description Detect flow from a sensitive node to file access (FileSystemAccess)
 * @author Fabian Froh
 * @kind path-problem
 * @id js/sensitive-node-file-access
 * @security-severity 8.0
 * @package-examples font-scrubber
 * @tags file access
 *       sensitive node
 */


 import javascript
 import DataFlow::PathGraph
 
 class SensitiveNodeFileAccessConfiguration extends TaintTracking::Configuration {
  SensitiveNodeFileAccessConfiguration() { this = "SensitiveNodeFileAccessConfiguration" }
 
   override predicate isSource(DataFlow::Node source) {
    source instanceof SensitiveNode
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
 
 from SensitiveNodeFileAccessConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "SensitiveNode ($@) classified as \"" + source.getNode().(SensitiveNode).getClassification() + "\" is used to access a file ($@).", source.getNode(), source.toString(), sink.getNode(), sink.toString()