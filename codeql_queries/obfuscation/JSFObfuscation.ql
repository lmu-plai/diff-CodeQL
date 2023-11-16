/**
 * @name JSF obfuscated code
 * @description Detects JSF obfuscated code / esoteric programming style
 * @author Fabian Froh
 * @kind problem
 * @id js/jsf-obfuscation
 * @security-severity 8.0
 * @example-packages jsf-obfuscation (custom)
 * @tags security
 * obfuscation
 * esoteric programming style
 * 6chars
 */

 import javascript

 // JSF code can be any node
 from AstNode a

 // Detect JSF code: 
 // http://www.jsfuck.com/ 
 // https://en.wikipedia.org/wiki/JSFuck
 // where code is written using only six characters: [, ], (, ), !, and +
 where a.toString().regexpMatch("[\\.\\+\\!\\(\\)\\[\\]\\\\ ]{10,}")

 select a, "Detected JSF code (\"" + a.toString() + "\")"