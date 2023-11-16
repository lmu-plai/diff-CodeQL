/**
 * @name Variable access by index expression with parent binary expression
 * @description Detects a large number of index expressions with parent binary expression that access the same variable/array indicating obfuscation
 * @author Fabian Froh
 * @kind problem
 * @id js/var-access-by-index-expression
 * @security-severity 10.0
 * @package-examples vue-backbone pm-controls
 * @tags security
 * obfuscation
 * obfuscator tool
 * variable reference
 * array indexing
 */

import javascript

// Count the deepth of the binary expression (e.g. "B + B + B" has deepth of 3)
int countDeepth(BinaryExpr b) {
    if b.getParentExpr() instanceof BinaryExpr then
        result = countDeepth(b.getParentExpr()) + 1
    else 
        result = 0
}

from Assignment a, int c
// IndexExpr with parent BinaryExpr referencing the same Var is common for a obfuscation technique
// Includes check if it is all in the same file otherwise a lot of false positives
where c = count(IndexExpr i | i.getBase().toString() = a.getLhs().toString() and i.getParentExpr() instanceof BinaryExpr and countDeepth(i.getParentExpr()) > 5 and a.getFile() = i.getFile()) 
// Define a threshold for the count of references
and c > 30
select a, "Variable '" + a.getLhs().toString() + "' is accessed " + c + " times by index expression with parent binary expressions of deepth > 5."
