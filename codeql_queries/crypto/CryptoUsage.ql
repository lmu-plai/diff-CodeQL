/**
 * @name Usage of crypto
 * @description Detects usage of functions "createDecipher", "update", "final" of crypto module
 * @author Fabian Froh
 * @kind problem
 * @id js/crypto-usage
 * @security-severity 2.0
 * @package-examples flatmap-stream
 * @tags security
 * crypto
 * createDeciper
 * update
 * final
 */

 import javascript
 
 from CallExpr c
 where c.getCalleeName().toString() in ["createDecipher", "update", "final"]
 select c, "Found usage of crypto function \"" + c.getCalleeName().toString() + "\" with first argument \"" + c.getArgument(0) + "\""