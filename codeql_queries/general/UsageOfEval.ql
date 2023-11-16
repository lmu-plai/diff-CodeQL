/**
 * @name Detects any eval function call
 * @description The eval() function evaluates JavaScript code represented as a string and returns its completion value. The source is parsed as a script.
 * @author Fabian Froh
 * @kind problem
 * @id js/usage-of-eval
 * @security-severity 5.0
 * @package-examples eslint-scope eslint-config-eslint 
 * @tags security 
 * eval
 * arbitrary_code_execution
 */

 import javascript
 import relevantCodeUtils

 from DirectEval e
 select e, "Found use of direct eval with argument ($@) in code.", e, getArgumentAsString(e.getAnArgument())