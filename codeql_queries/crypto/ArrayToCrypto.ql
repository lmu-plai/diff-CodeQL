/**
 * @name Flow from array to crypto
 * @description Detects flow from Array to createDeciper, update of final method of crypto module
 * @author Fabian Froh
 * @kind path-problem
 * @id js/array-to-crypto
 * @security-severity 5.0
 * @package-examples flatmap-stream (flatmap-stream_deobfuscated)
 * @tags security
 * crypto
 * createDeciper
 * update
 * final
 */

 import javascript
 import semmle.javascript.security.CryptoAlgorithms
 import DataFlow::PathGraph
 
 class ArrayToCryptoConfiguration extends TaintTracking::Configuration {
    ArrayToCryptoConfiguration() { this = "ArrayToCryptoConfiguration" }
 
   override predicate isSource(DataFlow::Node source) {
     //source instanceof DataFlow::ArrayLiteralNode
     exists(string s, DataFlow::ArrayLiteralNode a | source.mayHaveStringValue(s) | source = a.getAnElement())
   }
 
   override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode m | m.getMethodName() in ["createDecipher", "update", "final"] | sink = m.getAnArgument())
  }

   // TODO: try to add additional taint step for obfuscated flatmap
   override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Storing the information in an object property
    // Passed as an argument: https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-javascript-and-typescript/#analyzing-data-flow-in-javascript-and-typescript
    exists(DataFlow::CallNode c | pred = c.getAnArgument() and succ = c) or
    // Storing the information in an object property
    exists( DataFlow::PropWrite propWrite, string property
        | propWrite.writes(succ, property, pred)
        ) or
    exists(DataFlow::ParameterNode c | pred = c and succ = c.getAFunctionValue())
     }
   
 }

 // Get the full string value
string getStringValue(DataFlow::PathNode node) {
  node.getNode().mayHaveStringValue(result)
}
 
 from ArrayToCryptoConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "Array element of array ($@) is used in crypto function \"" + 
 ((MethodCallExpr)sink.getNode().getAstNode().getParent()).getCalleeName() + "\" as an argument ($@).", source.getNode(), getStringValue(source), sink.getNode(), sink.toString()