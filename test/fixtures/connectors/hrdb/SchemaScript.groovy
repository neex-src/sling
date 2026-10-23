// ScriptedSQL schema: one account class, the columns IDM may map.
import org.identityconnectors.framework.common.objects.ObjectClass
import static org.identityconnectors.framework.common.objects.AttributeInfo.Flags.REQUIRED

builder.schema({
    objectClass {
        type ObjectClass.ACCOUNT_NAME
        attributes {
            firstname String.class
            lastname String.class
            fullname String.class
            email String.class
            organization String.class
        }
    }
})
