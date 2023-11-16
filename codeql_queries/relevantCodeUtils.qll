/**
 * @Author Fabian Froh
 */

 import javascript


string getHostnameOrIPAddressOfClientRequestAsString(ClientRequest c) {
    if c.getUrl().getAstNode() instanceof ObjectExpr
    then result = ((ObjectExpr)c.getUrl().getAstNode()).getPropertyByName("hostname").getChildExpr(1).getStringValue()
    else if exists(string s | c.getAnArgument().mayHaveStringValue(s))
    then result = c.getAnArgument().getStringValue()
    else result = c.getUrl().toString() // Or do not return anything?
}

string getHostnameOrIPAddressOfParentClientRequestAsString(DataFlow::PathNode node) {
    // Get parent and cast to client request to use existing method for getting URL/IP address
    result = getHostnameOrIPAddressOfClientRequestAsString((ClientRequest)node.getNode().asExpr().getParentExpr().flow())
}

string getFirstCallExprArgumentAsString(DataFlow::PathNode node) {
    ((CallExpr)node.getNode().asExpr()).getArgument(0).toString() = result
}


string getArgumentAsString(Expr e) {

    if e instanceof VarRef
    then result = ((VarRef)e).getAVariable().toString()
    else if exists(string s | e.mayHaveStringValue(s))
    then result = e.getStringValue()
    else result = e.toString()
    
}