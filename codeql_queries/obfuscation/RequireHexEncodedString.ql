/**
 * @name Require with hexadecimal encoded string agrgument
 * @description Detects flow from hexadecimal encoded string with \x prefix to require statement which can indicate obfuscation
 * @author Fabian Froh
 * @kind path-problem
 * @id js/require-hex-encoded-string
 * @security-severity 10.0
 * @example-packages getcookies
 * @tags security
 * require
 * obfuscation
 * string
 * hexadecimal characaters
 */

import javascript
import DataFlow::PathGraph

class RequireHexEcnodedStringConfiguration extends TaintTracking::Configuration {
    RequireHexEcnodedStringConfiguration() { this = "RequireHexEcnodedStringConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    // Match two or more repetitions of hexadecimal chars with "\x" at the beginning of each char
    source.asExpr() instanceof StringLiteral and ((StringLiteral)source.asExpr()).getRawValue().regexpMatch(".*\\\\x[0-9a-fA-F]{2,}.*")
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Require r | sink.asExpr() = r.getAnArgument())
  }
}

from RequireHexEcnodedStringConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
// s.getRawValue() is in single quotes by default
select sink.getNode(), source, sink, "Found require statement with hex encoded string " +  ((StringLiteral)source.getNode().asExpr()).getRawValue() + " as argument that decodes to '" + ((StringLiteral)source.getNode().asExpr()).getStringValue() + "'."