// ScriptedSQL test: the connection works and the table is there.
import groovy.sql.Sql
new Sql(connection).firstRow("SELECT count(*) AS n FROM employees")
