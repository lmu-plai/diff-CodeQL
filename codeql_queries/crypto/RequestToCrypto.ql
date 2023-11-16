/**
 * @name Flow from request to crypto
 * @description Detects flow from request to createDeciper, update of final method of crypto module
 * @Author Fabian Froh
 * @kind path-problem
 * @id js/request-to-crypto
 * @package-examples ??? 
 * @tags crypto
 * createDeciper
 * update
 * final
 * request
 */

 import javascript
 import semmle.javascript.security.CryptoAlgorithms
 import DataFlow::PathGraph
 
 class RequestToCryptoConfiguration extends TaintTracking::Configuration {
  RequestToCryptoConfiguration() { this = "RequestToCryptoConfiguration" }
 
   override predicate isSource(DataFlow::Node source) {
     source instanceof ClientRequest
   }
 
   override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode m | m.getMethodName() in ["createDecipher", "update", "final"] | sink = m.getArgument(0))
   }
   
 }
 
 from RequestToCryptoConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "Request data ($@) is used in crypto function ($@).", source.getNode(), source.toString(), sink.getNode(), sink.toString()