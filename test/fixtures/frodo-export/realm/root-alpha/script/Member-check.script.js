// Members (mail in the domain held by an ESV) go on to the preferences journey; everyone else is done.
var user = openidm.read("managed/alpha_user/" + nodeState.get("_id"));
var domain = systemEnv.getProperty("esv.member.domain");
if (user && String(user.mail).endsWith("@" + domain)) {
  action.goTo("member").putSessionProperty("member", "true");
} else {
  action.goTo("guest");
}
