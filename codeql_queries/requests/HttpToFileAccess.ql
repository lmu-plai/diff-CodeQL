/**
 * @name Network data written to file
 * @description Writing network data directly to the file system allows arbitrary file upload and might indicate a backdoor.
 * @Author CodeQL Community
 * @kind path-problem
 * @id js/http-to-file-access
 * @example-packages TODO
 * @security-severity 5.0
 * @url https://codeql.github.com/codeql-query-help/javascript/js-http-to-file-access/
 * @tags security
 *       external/cwe/cwe-912
 *       external/cwe/cwe-434
 */

 import javascript
 import semmle.javascript.security.dataflow.HttpToFileAccessQuery
 import DataFlow::PathGraph
 
 from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "Write to file system ($@) depends on untrusted data ($@)", source.getNode(), source.toString(), sink.getNode(), sink.toString()