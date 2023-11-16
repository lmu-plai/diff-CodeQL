/**
 * @name IP address in install script line
 * @description Detects if there is a ip address in install script line of package.json
 * @Author Fabian Froh
 * @kind problem
 * @id js/install-script-ip-address
 * @package-examples slack-reacjilator
 * @tags ip_address
 * install script
 * preinstall
 * postinstall
 */

import javascript

from JsonObject json, string scriptName, string scriptCode
where exists( PackageJson manifest | json = manifest.getScripts() )
  and scriptName = [ "preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare" ]
  and scriptCode = json.getPropStringValue(scriptName) 
  and scriptCode.regexpMatch(".*(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).*")
select json, "Detected IP address in \"" + scriptName + "\" script with code \"" + scriptCode + "\""
