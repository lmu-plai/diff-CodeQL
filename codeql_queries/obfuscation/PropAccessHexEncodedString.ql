/**
 * @name Property access using hexadecimal encoded string
 * @description Detects data flow from a hexadecimal encoded string with \x prefix to a property access that can indicate obfuscation
 * @author Fabian Froh
 * @kind path-problem
 * @id js/prop-access-hex-encoded-string
 * @security-severity 10.0
 * @example-packages getcookies
 * @tags security
 * property access
 * obfuscation
 * string
 * hexadecimal characaters
 */

import javascript
import DataFlow::PathGraph

class PropAccessHexEncodedStringConfiguration extends TaintTracking::Configuration {
    PropAccessHexEncodedStringConfiguration() { this = "PropAccessHexEncodedStringConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    // Match two or more repetitions of hexadecimal chars with "\x" at the beginning of each char
    source.asExpr() instanceof StringLiteral and ((StringLiteral)source.asExpr()).getRawValue().regexpMatch(".*\\\\x[0-9a-fA-F]{2,}.*")
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(PropAccess a | sink.asExpr() = a.getPropertyNameExpr())
  }
}

from PropAccessHexEncodedStringConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
// s.getRawValue() is in single quotes by default
select sink.getNode(), source, sink, "Found property access using hex encoded string " +  ((StringLiteral)source.getNode().asExpr()).getRawValue() + " that decodes to '" + ((StringLiteral)source.getNode().asExpr()).getStringValue() + "'."
