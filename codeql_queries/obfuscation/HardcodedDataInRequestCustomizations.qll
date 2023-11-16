/**
 * Provides default sources, sinks and sanitizers for reasoning about
 * hard-coded data flowing to / in a client request.
 */

 import javascript
 private import semmle.javascript.security.dataflow.CodeInjectionCustomizations
 
 module HardcodedDataInRequest {
   /**
    * A data flow source for hard-coded data.
    */
   abstract class Source extends DataFlow::Node {
     /** Gets a flow label for which this is a source. */
     DataFlow::FlowLabel getLabel() { result.isData() }
   }
 
   /**
    * A data flow sink for a client request.
    */
   abstract class Sink extends DataFlow::Node {
     /** Gets a flow label for which this is a sink. */
     abstract DataFlow::FlowLabel getLabel();
 
     /** Gets a description of what kind of sink this is. */
     abstract string getKind();
   }
 
   /**
    * A sanitizer for hard-coded data.
    */
   abstract class Sanitizer extends DataFlow::Node { }
 
   /**
    * A constant string consisting of eight or more hexadecimal characters (including at
    * least one digit), viewed as a source of hard-coded data that should not be
    * interpreted as code.
    * => Customized -> also check for \x hex encoding and two or more hex characters
    */
   private class DefaultSource extends Source, DataFlow::ValueNode {
     DefaultSource() {
      exists(string val | val = astNode.(Expr).getStringValue() |
         val.regexpMatch("[0-9a-fA-F]{2,}") and
         val.regexpMatch(".*[0-9].*")
         ) or
         
         exists(string val | val = astNode.(Expr).getStringValue() |
         val.regexpMatch(".*\\\\x[0-9a-fA-F]{2,}.*")
         )
     }
   }
 
   /**
    * An argument to a client request; hard-coded (obfuscated) data should not flow here.
    */
   private class ClientRequestSink extends Sink {
    ClientRequestSink() { this = any(ClientRequest cr).getAnArgument() }
 
     override DataFlow::FlowLabel getLabel() { result.isDataOrTaint() }
 
     override string getKind() { result = "An client request" }
   }
 }