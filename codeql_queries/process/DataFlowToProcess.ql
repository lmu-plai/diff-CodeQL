/**
 * @name Data flow string to process
 * @description Detects any string data flow to a process
 * @author Fabian Froh
 * @kind path-problem
 * @id js/data-flow-to-process
 * @security-severity 4.0
 * @package-examples benign-to-malicous-process-exec
 * @tags process
 *       data flow
 *       string
 */


import javascript
import DataFlow::PathGraph

// Import own module
import relevantCodeUtils

class DataFlowToProcessConfiguration extends TaintTracking::Configuration {
  DataFlowToProcessConfiguration() { this = "DataFlowToProcessConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    // Detect string values that flow to command execution
    source.asExpr() instanceof StringLiteral or source instanceof StringOps::Concatenation
    //exists(string s| source.mayHaveStringValue(s))
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SystemCommandExecution c | sink = c.getACommandArgument())
  }

  //override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
  //}
  
}

from DataFlowToProcessConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink) and not source.getNode() = sink.getNode()
select sink.getNode(), source, sink, "Data flow from string ($@) to system command execution / process ($@).", source.getNode(), source.getNode().getStringValue(), sink.getNode(), getArgumentAsString(sink.getNode().asExpr())