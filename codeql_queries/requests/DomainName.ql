/**
 * @name Detects domain names
 * @description Detects domain names as StringLiteral using a regular expression
 * @author Fabian Froh
 * @kind problem
 * @id js/domain-name
 * @security-severity 2.0
 * @example-packages eslint-scope
 * @tags security
 * domain name
 */

import javascript

from StringLiteral s

// First try to detect any domain name:
//where s.toString().regexpMatch(".*(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,63}.*")
// (?i) -> makes the match case-insensitive

// Detect most common tlds
where s.getStringValue().regexpMatch("(?i).*\\.(com|net|org|jp|de|uk|fr|br|it|ru|es|me|gov|pl|ca|au|cn|co|" +
    "in|nl|edu|info|eu|ch|id|at|kr|cz|mx|be|tv|se|tr|tw|al|ua|ir|vn|cl|sk|ly|cc|to|no|fi|us|pt|dk|ar|hu|tk|" +
    "gr|il|news|ro|my|biz|ie|za|nz|sg|ee|th|io|xyz|pe|bg|hk|rs|lt|link|ph|club|si|site|mobi|by|cat|wiki|la|" +
    "ga|xxx|cf|hr|ng|jobs|online|kz|ug|gq|ae|is|lv|pro|fm|tips|ms|sa|app)") 

// Ignore all findings in import statements (that includes require)
//and not s.getParentExpr() instanceof Import
//and not s.getEnclosingStmt() instanceof Import

select s, "Detected the following domain name: " + s.getStringValue()