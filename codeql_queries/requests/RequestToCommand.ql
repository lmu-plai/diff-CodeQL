/**
 * @name Flow from request to command
 * @description Request from http.createServer or response form ClientRequest is used in command (SystemCommandExecution)
 * @Author Fabian Froh based on Matías Gobbi
 * @kind path-problem
 * @id js/request-to-command
 * @package-examples fc-gotcha (security example package)
 * @tags command
 *       request reponse
 *       createServer
 *       http
 */


import javascript
// import semmle.javascript.frameworks.HTTP
import DataFlow::PathGraph

class RequestToCommandConfiguration extends TaintTracking::Configuration {
  RequestToCommandConfiguration() { this = "RequestToCommandConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    exists( Http::ServerDefinition server, Http::RouteHandler handler
      | handler = server.getARouteHandler()
      | source = handler.getARequestSource()
      )
    or source instanceof ClientRequest
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SystemCommandExecution c | sink = c.getACommandArgument())
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    succ = pred.(ClientRequest).getAResponseDataNode()
  }
  
}

from RequestToCommandConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Request or response ($@) is used in system command ($@).", source.getNode(), source.toString(), sink.getNode(), sink.toString()