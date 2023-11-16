/**
 * @name Domain in install script line
 * @description Detects if there is a domain name in install script line of package.json
 * @Author Fabian Froh
 * @kind problem
 * @id js/install-script-domain-name
 * @package-examples ???
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
  and scriptCode.regexpMatch("(?i).*\\.(com|net|org|jp|de|uk|fr|br|it|ru|es|me|gov|pl|ca|au|cn|co|" +
  "in|nl|edu|info|eu|ch|id|at|kr|cz|mx|be|tv|se|tr|tw|al|ua|ir|vn|cl|sk|ly|cc|to|no|fi|us|pt|dk|ar|hu|tk|" +
  "gr|il|news|ro|my|biz|ie|za|nz|sg|ee|th|io|xyz|pe|bg|hk|rs|lt|link|ph|club|si|site|mobi|by|cat|wiki|la|" +
  "ga|xxx|cf|hr|ng|jobs|online|kz|ug|gq|ae|is|lv|pro|fm|tips|ms|sa|app)") 
  
select json, "Detected domain name in \"" + scriptName + "\" script with code \"" + scriptCode + "\""
