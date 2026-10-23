// ScriptedSQL update: set the attributes given, keep the rest.
import groovy.sql.Sql

def cols = evaluate(new File(configuration.scriptRoots[0], "columns.groovy"))
def sets = [:]
attributes.each { a -> if (cols[a.name]) sets[cols[a.name]] = a.value ? a.value[0] : null }
if (sets) {
    def keys = sets.keySet().toList()
    new Sql(connection).executeUpdate(
            "UPDATE employees SET " + keys.collect { it + " = ?" }.join(", ") + ", updated_at = now() WHERE id = ?",
            keys.collect { sets[it] } + [uid.uidValue as Integer])
}
uid
