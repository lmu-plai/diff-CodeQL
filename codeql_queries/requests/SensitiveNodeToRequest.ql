/**
 * @name Flow from SensitiveNode to a request
 * @description Detect flow from a sensitive node to a request (ClientRequest)
 * @author Fabian Froh
 * @kind path-problem
 * @id js/sensitive-node-to-request
 * @security-severity 9.0
 * @package-examples ???
 * @tags security
 * request
 * sensitive node
 */


 import javascript
 import DataFlow::PathGraph

 // Import own module
 import relevantCodeUtils
 
 class SensitiveNodeToRequestConfiguration extends TaintTracking::Configuration {
      SensitiveNodeToRequestConfiguration() { this = "SensitiveNodeToRequestConfiguration" }
 
   override predicate isSource(DataFlow::Node source) {
     exists(SensitiveNode c | source.getStringValue() = c.getStringValue())
   }
 
   override predicate isSink(DataFlow::Node sink) {
      exists(ClientRequest c | sink = c.getAnArgument())
   }
 
   override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
     // Storing the information in an object property
     exists( DataFlow::PropWrite propWrite, string property
           | propWrite.writes(succ, property, pred)
           )
     }
 }
 
 from SensitiveNodeToRequestConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "SensitiveNode ($@) classified as \"" + source.getNode().(SensitiveNode).getClassification() + "\" flows to a request argument ($@).", source.getNode(), source.getNode().getStringValue(), sink.getNode(), getHostnameOrIPAddressOfClientRequestAsString(sink.getNode())