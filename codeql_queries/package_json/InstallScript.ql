/**
 * @name Detects install script
 * @description Detects all install scripts in package.json
 * @author Fabian Froh
 * @kind problem
 * @id js/install-script
 * @security-severity 7.0
 * @package-examples eslint-scope
 * @tags security
 *       script
 *       install script
 */

import javascript

from JsonObject json, string scriptName, string scriptCode
where exists( PackageJson manifest | json = manifest.getScripts() )
  and scriptName = [ "preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare" ]
  and scriptCode = json.getPropStringValue(scriptName)
select json, "Detected \"" + scriptName + "\" script with code \"" + scriptCode + "\""
