/**
 * @name Flow from encoded string to decode and require
 * @description Detects the flow from an encoded string to a decode function and finally to a require (call)
 * @author Matías Gobbi
 * @kind path-problem
 * @id js/encoded-string-require
 * @security-severity 10.0
 * @package-examples flatmap-stream
 * @tags security
 *       taint-traking
 *       financial-gain
 */

import javascript
import DataFlow::PathGraph

// Our own module...
import utilities
import relevantCodeUtils


class Initial_Node extends DataFlow::Node {
  Initial_Node() {
    this instanceof DataFlow::SourceNode
    and
    exists(string encoded | this.mayHaveStringValue(encoded))
  }
}

class Middle_Node extends DataFlow::Node {
  Middle_Node() {
    this instanceof Encoding::StringDecoderNode
  }
}

class Final_Node extends DataFlow::Node {
  Final_Node() {
    exists( Require require, DataFlow::InvokeNode requireCall
          | requireCall = require.flow()
          | this = requireCall.getAnArgument()
          )
  }
}


// Taint-Tracking: Encoded String ---> Decoded String
class Encoded_to_Decoded_Configuration extends TaintTracking::Configuration {
  Encoded_to_Decoded_Configuration() { this = "Encoded ---> Decoded" }

  // Source: Encoded string
  override predicate isSource(DataFlow::Node source) { source instanceof Initial_Node }

  // Sink: Decoded string
  override predicate isSink(DataFlow::Node sink) { sink instanceof Middle_Node }
}


// Taint-Tracking: Decoded String ---> Require Package
class Decoded_to_Require_Configuration extends TaintTracking::Configuration {
  Decoded_to_Require_Configuration() { this = "Decoded ---> Require" }

  // Source: Decoded string
  override predicate isSource(DataFlow::Node source) { source instanceof Middle_Node }

  // Sink: Require package
  override predicate isSink(DataFlow::Node sink) { sink instanceof Final_Node }
}


// Taint-Tracking: Full Path
class FullConfiguration extends TaintTracking::Configuration {
  FullConfiguration() { this = "Full Path" }

  // Source: Encoded string
  override predicate isSource(DataFlow::Node source) { source instanceof Initial_Node }

  // Sink: Require package
  override predicate isSink(DataFlow::Node sink) { sink instanceof Final_Node }
}


from FullConfiguration full_CFG, DataFlow::PathNode full_source, DataFlow::PathNode full_sink,
     Encoded_to_Decoded_Configuration init_CFG, DataFlow::PathNode init_source, DataFlow::PathNode init_sink,
     Decoded_to_Require_Configuration last_CFG, DataFlow::PathNode last_source, DataFlow::PathNode last_sink
where full_CFG.hasFlowPath(full_source, full_sink)
  and init_CFG.hasFlowPath(init_source, init_sink)
  and last_CFG.hasFlowPath(last_source, last_sink)
  and full_source.getNode() = init_source.getNode()
  and init_sink.getNode() = last_source.getNode()
  and last_sink.getNode() = full_sink.getNode()
select full_sink.getNode(),
       full_source,
       full_sink,
       "Flow from encoded string ($@) to decode and then to require as argument ($@)",
       full_source.getNode(),
       full_source.getNode().getStringValue(),
       full_sink.getNode(),
       getArgumentAsString(full_sink.getNode().asExpr())
       
