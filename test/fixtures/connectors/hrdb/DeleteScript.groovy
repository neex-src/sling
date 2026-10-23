// ScriptedSQL delete.
import groovy.sql.Sql
import org.identityconnectors.framework.common.exceptions.UnknownUidException

if (new Sql(connection).executeUpdate("DELETE FROM employees WHERE id = ?", [uid.uidValue as Integer]) == 0) {
    throw new UnknownUidException(uid, objectClass)
}
