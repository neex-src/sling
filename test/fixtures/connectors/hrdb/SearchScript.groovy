// ScriptedSQL search: the ICF filter (as the `query` map) becomes a WHERE clause.
import groovy.sql.Sql

def cols = evaluate(new File(configuration.scriptRoots[0], "columns.groovy")) + [__UID__: "id"]
def params = []
def where
where = { q ->
    if (q == null) return "TRUE"
    switch (q.operation) {
        case "AND": return "(" + where(q.left) + " AND " + where(q.right) + ")"
        case "OR": return "(" + where(q.left) + " OR " + where(q.right) + ")"
    }
    def col = cols[q.left]
    if (!col) throw new IllegalArgumentException("cannot search on " + q.left)
    def v = col == "id" ? (q.right as Integer) : q.right
    def sql
    switch (q.operation) {
        case "EQUALS": sql = col + " = ?"; params << v; break
        case "CONTAINS": sql = col + " LIKE ?"; params << "%" + v + "%"; break
        case "STARTSWITH": sql = col + " LIKE ?"; params << v + "%"; break
        case "ENDSWITH": sql = col + " LIKE ?"; params << "%" + v; break
        case "GREATERTHAN": sql = col + " > ?"; params << v; break
        case "GREATERTHANOREQUAL": sql = col + " >= ?"; params << v; break
        case "LESSTHAN": sql = col + " < ?"; params << v; break
        case "LESSTHANOREQUAL": sql = col + " <= ?"; params << v; break
        default: throw new IllegalArgumentException("operation " + q.operation)
    }
    q.not ? "NOT (" + sql + ")" : sql
}
def clause = where(query())
new Sql(connection).eachRow("SELECT * FROM employees WHERE " + clause + " ORDER BY id", params) { r ->
    handler {
        uid r.id as String
        id r.username
        attribute "firstname", r.first_name
        attribute "lastname", r.last_name
        attribute "fullname", r.full_name
        attribute "email", r.email
        attribute "organization", r.department
    }
}
