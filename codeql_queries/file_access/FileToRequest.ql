/**
 * @name Flow from file to request
 * @description Data flow from a file source (FileSystemAccess) to a network sink (ClientRequest)
 * @Author Fabian Froh
 * @kind path-problem
 * @id js/file-to-request
 * @package-examples eslint-scope (with payload.js)
 * @tags file access
 *       network request
 */


import javascript
import DataFlow::PathGraph
import relevantCodeUtils

class FileToRequestConfiguration extends TaintTracking::Configuration {
  FileToRequestConfiguration() { this = "FileToRequestConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof FileSystemAccess
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(ClientRequest c | sink = c.getAnArgument())
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Storing the information in an object property
    exists( DataFlow::PropWrite propWrite, string property
          | propWrite.writes(succ, property, pred)
          )
    }
}

from FileToRequestConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "File data ($@) is used in client request ($@).", source.getNode(), getFirstCallExprArgumentAsString(source), sink.getNode(), getHostnameOrIPAddressOfParentClientRequestAsString(sink)