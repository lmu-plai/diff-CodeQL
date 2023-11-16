/**
 * @name Detects domain names
 * @description Detects domain names as String concatenations using a regular expression
 * @Author Fabian Froh
 * @kind problem
 * @id js/domain-name-concat
 * @security-severity 4.0
 * @example-packages benign-to-malicious-request (custom)
 * @tags domain name
 *       string concatenation
 */

import javascript

// Get all string concats
from StringOps::ConcatenationNode c

// Detect most common tlds
where c.getStringValue().regexpMatch("(?i).*\\.(com|net|org|jp|de|uk|fr|br|it|ru|es|me|gov|pl|ca|au|cn|co|" +
"in|nl|edu|info|eu|ch|id|at|kr|cz|mx|be|tv|se|tr|tw|al|ua|ir|vn|cl|sk|ly|cc|to|no|fi|us|pt|dk|ar|hu|tk|" +
"gr|il|news|ro|my|biz|ie|za|nz|sg|ee|th|io|xyz|pe|bg|hk|rs|lt|link|ph|club|si|site|mobi|by|cat|wiki|la|" +
"ga|xxx|cf|hr|ng|jobs|online|kz|ug|gq|ae|is|lv|pro|fm|tips|ms|sa|app)") 

select c, "Detected the following domain name: " + c.getStringValue()