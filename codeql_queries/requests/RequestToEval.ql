/**
 * @name Flow from request to eval
 * @description Response of a request (ClientRequest) is used in direct eval function
 * @author Fabian Froh
 * @kind path-problem
 * @id js/request-to-eval
 * @security-severity 10.0
 * @package-examples eslint-scope
 * @tags security
 *       eval
 *       request reponse
 */


import javascript
import DataFlow::PathGraph

// Import own module
import relevantCodeUtils

class RequestToEvalConfiguration extends TaintTracking::Configuration {
  RequestToEvalConfiguration() { this = "RequestToEvalConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ClientRequest
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DirectEval e | sink = e.getAnArgument().flow())
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    succ = pred.(ClientRequest).getAResponseDataNode()
  }
  
}

from RequestToEvalConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Request response ($@) is used in direct eval function ($@).", source.getNode(), getHostnameOrIPAddressOfClientRequestAsString(source.getNode()) , sink.getNode(), getArgumentAsString(sink.getNode().asExpr())