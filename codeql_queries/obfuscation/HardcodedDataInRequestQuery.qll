/**
 * Provides a taint-tracking configuration for reasoning about hard-coded data
 * flowing to / in a request
 *
 */

 import javascript
 import HardcodedDataInRequestCustomizations::HardcodedDataInRequest
 
 /**
  * A taint-tracking configuration for reasoning about hard-coded data
  * flowing to / in a request
  */
 class Configuration extends TaintTracking::Configuration {
   Configuration() { this = "HardcodedDataInRequest" }
 
   override predicate isSource(DataFlow::Node source, DataFlow::FlowLabel lbl) {
     source.(Source).getLabel() = lbl
   }
 
   override predicate isSink(DataFlow::Node nd, DataFlow::FlowLabel lbl) {
     nd.(Sink).getLabel() = lbl
   }
 
   override predicate isSanitizer(DataFlow::Node node) { node instanceof Sanitizer }
 }