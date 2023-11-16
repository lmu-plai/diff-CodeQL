/**
 * @Author Matías Gobbi
 */

import javascript


module Require {

    // Indirect use of NPM's require functionality
    class Require_Reference extends DataFlow::ModuleImportNode::Range, DataFlow::InvokeNode {
        // CharPred
        Require_Reference() {
            exists( DataFlow::SourceNode proc, DataFlow::PropRead main, DataFlow::PropRead cons, DataFlow::PropRead load
                  | proc = DataFlow::globalVarRef("process")
                and main = proc.getAPropertyRead("mainModule")
                and cons = main.getAPropertyRead("constructor")
                and load = cons.getAPropertyRead("_load")
                  | load.flowsTo(this.getCalleeNode())
                  )
        }

        // Gets the PATH of the imported module
        override string getPath() {
            this.getAnArgument().mayHaveStringValue(result)
        }
    }

}


module Cryptography {

    // Cryptographic Algorithm used to encode information
    class Cryptographic_Algorithm extends DataFlow::Node {
        // Characteristic Predicate
        Cryptographic_Algorithm() {
            exists( DataFlow::InvokeNode cipher, CryptographicKey key
                  | cipher.getAnArgument() = key
                  | cipher.flowsTo(this)
                  )
        }
    }

    // Cryptographic Operation used to encode information
    class Cryptographic_Operation extends DataFlow::MethodCallNode {
        // Characteristic Predicate
        Cryptographic_Operation() {
            exists( Cryptographic_Algorithm algorithm, string method
                  | this.calls(algorithm, method)
                  )
        }
    }

}


module Encoding {

    // Decoding step for a node that contains an encoded string
    class StringDecoderNode extends DataFlow::Node {
        // CharPred
        StringDecoderNode() {
            exists( DataFlow::InvokeNode decoder, DataFlow::SourceNode buffer
                  | buffer = DataFlow::globalVarRef("Buffer") and decoder = buffer.getAMemberInvocation("from")
                  | decoder.getArgument(0) = this
                and decoder.getArgument(1).mayHaveStringValue(["binary", "base64", "hex", "ascii"])
                  )
        }
    }

    // Decoding step for a node that contains an array
    class ArrayDecoderNode extends DataFlow::Node {
        // CharPred
        ArrayDecoderNode() {
            exists( DataFlow::InvokeNode decoder, DataFlow::SourceNode buffer
                  | buffer = DataFlow::globalVarRef("Buffer") and decoder = buffer.getAMemberInvocation("from")
                  | decoder.getAnArgument() = this and decoder.getNumArgument() = 1
                  )
        }
    }

}


module Request_Utils {

    // Common property names for specifying domains
    class DomainProperty extends string {
        //CharPred
        DomainProperty() {
            this in [ "host", "hostname", "url" ]
        }
    }

    // Flow from OPTIONS to Request
    class Request_OPTIONS extends TaintTracking::Configuration {
        Request_OPTIONS() { this = "OPTIONS as an {object}" }

        // Source: OPTIONS as an object
        override predicate isSource(DataFlow::Node source) {
            exists( ObjectExpr objectURL, Property propertyURL, DomainProperty prop, Expr initURL, DataFlow::SourceNode nodeURL
                  | source.asExpr() = objectURL
                and objectURL.getPropertyByName(prop) = propertyURL
                and propertyURL.getInit() = initURL
                and nodeURL.flowsTo(initURL.flow())
                  | nodeURL.mayHaveStringValue(_)
                  )
        }

        // Sink: Request URL
        override predicate isSink(DataFlow::Node sink) {
            exists( ClientRequest client | client.getUrl() = sink )
        }
    }

    // POST of some data to any Request
    class Request_Write extends DataFlow::Node {

        ClientRequest client;

        // CharPred
        Request_Write() {
            this = client.getAMemberCall("write").getAnArgument()
        }

        private predicate hasFlow() {
            exists( Request_OPTIONS request, DataFlow::Node source, DataFlow::Node sink
                  | request.hasFlow(source, sink)
                  // Connect the SINK
                  | client.getUrl() = sink
                  )
        }

        private predicate hasFlow(string stringURL) {
            exists( Request_OPTIONS request, DataFlow::Node source, DataFlow::Node sink
                  | request.hasFlow(source, sink)
                  // Connect the SINK
                  | client.getUrl() = sink
                  // Connect the SOURCE (Just to retrieve the URL)
                and exists( ObjectExpr objectURL, Property propertyURL, DomainProperty prop, Expr initURL, DataFlow::SourceNode nodeURL
                          | source.asExpr() = objectURL
                        and objectURL.getPropertyByName(prop) = propertyURL
                        and propertyURL.getInit() = initURL
                        and nodeURL.flowsTo(initURL.flow())
                          | nodeURL.mayHaveStringValue(stringURL)
                          )
                  )
        }

        // Get some Domain URL (when specified as literal string)
        string getDomainURL() {
            if hasFlow()
            then hasFlow(result)
            else result = "No literal URL"
        }
    }

}

// TODO: Not only .mayHaveStringValue(...) but also root of StringConcat (like in package @drfarm@grid)