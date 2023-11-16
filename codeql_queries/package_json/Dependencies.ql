/**
 * @name Dependencies of package
 * @description Detects all dependencies of a npm packages
 * @author Fabian Froh
 * @kind problem
 * @id js/dependencies
 * @security-severity 0.0
 * @package-examples *any*
 * @tags dependency
 * package.json
 */

import javascript
import semmle.javascript.dependencies.Dependencies

from ExternalNpmDependency d
select d, "Found dependency: " + d.getNpmPackageName() + "-" + d.getVersion()