/**
 * @name Accessed file with sensitive name
 * @description Detect access (FileSystemAccess) to a file with a sensitive name (e.g. ssh)
 * @Author Fabian Froh based on work from Matías Gobbi
 * @kind path-problem
 * @id js/sensitive-file-name-access
 * @package-examples font-scrubber
 * @tags file access
 *       ssh
 *       sensitive file name
 *       passwd
 */


 import javascript
 import DataFlow::PathGraph

 class SensitiveFile extends string {
  // CharPred
  SensitiveFile() {
      this in [ "ssh/id_rsa"
              , "ssh/config"
              , "ssh/known_hosts"
              , "ssh/authorized_keys"
              , "bash_history"
              , "zsh_history"
              , "etc/passwd"
              , ".env"
              ]
  }
}
 
 class SensitiveFileNameAccessConfiguration extends TaintTracking::Configuration {
  SensitiveFileNameAccessConfiguration() { this = "SensitiveFileNameAccessConfiguration" }
 
   override predicate isSource(DataFlow::Node source) {
    exists( string path, SensitiveFile file
      | source.mayHaveStringValue(path)
      | path.matches( "%" + file )
      )
   }
 
   override predicate isSink(DataFlow::Node sink) {
     exists(FileSystemAccess f | sink = f.getAPathArgument()) 
   }
 
   override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
     // Storing the information in an object property
     exists( DataFlow::PropWrite propWrite, string property
           | propWrite.writes(succ, property, pred)
           )
     }
 }


 
 from SensitiveFileNameAccessConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "Sensitive file name ($@) is used in a file access ($@).", source.getNode(), source.getNode().getStringValue(), sink.getNode(), sink.toString()