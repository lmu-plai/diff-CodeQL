/**
 * @name Hexadecimal encoded string
 * @description Detects hexadecimal encoded string with \x prefix that can indicate obfuscation
 * @author Fabian Froh
 * @kind problem
 * @id js/hex-encoded-string
 * @security-severity 0.0
 * @example-packages getcookies
 * @tags obfuscation
 * string
 * hexadecimal characaters
 */

 import javascript

 from StringLiteral s

 // Match two or more repetitions of hexadecimal chars with "\x" at the beginning of each char
 where s.toString().regexpMatch(".*\\\\x[0-9a-fA-F]{2,}.*")

 // Matching of hexadecimal chars used from: 
 // https://github.com/github/codeql/blob/main/javascript/ql/lib/semmle/javascript/security/dataflow/HardcodedDataInterpretedAsCodeCustomizations.qll
 // This creates a lot of false positive because it matches a lot of benign strings
 //or s.toString().regexpMatch(".*[0-9a-fA-F]{2,}.*") and s.toString().regexpMatch(".*[0-9].*")

 select s, "Found string with hexadecimal characters (" + s.getRawValue() + ") that decodes to string value (" + s.getStringValue() + ")"