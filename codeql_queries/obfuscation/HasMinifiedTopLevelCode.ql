/**
 * @name Detect minified top level code
 * @description Detects top level code of files that is minified
 * @author Fabian Froh
 * @kind problem
 * @id js/has-minified-top-level-code
 * @security-severity 5.0
 * @package-examples vue-backbone
 * @tags security
 *       obfuscator
 *       minificator
 */

import javascript


from File file
where file.getATopLevel().isMinified()
select file, "Top level code of file ($@) is minified", file, file.getBaseName().toString()
