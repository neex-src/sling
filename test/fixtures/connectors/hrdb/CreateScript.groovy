// ScriptedSQL create: insert a row; the row id is the ICF uid.
import groovy.sql.Sql
import org.identityconnectors.framework.common.objects.Uid

def cols = evaluate(new File(configuration.scriptRoots[0], "columns.groovy"))
def values = [username: id]
attributes.each { a -> if (cols[a.name] && a.name != "__NAME__") values[cols[a.name]] = a.value ? a.value[0] : null }
def keys = values.keySet().toList()
def row = new Sql(connection).firstRow(
        "INSERT INTO employees (" + keys.join(", ") + ") VALUES (" + keys.collect { "?" }.join(", ") + ") RETURNING id",
        keys.collect { values[it] })
new Uid(row.id as String)
