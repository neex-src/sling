// Decide where a signed-in user goes next: staff on the corporate network step up, customers pass,
// anything risky is turned away. Uses nodeState, idRepository, requestHeaders, systemEnv and httpClient.
var username = nodeState.get("username");
var role = String(idRepository.getAttribute(username, "role").get(0));

var forwarded = requestHeaders.get("x-forwarded-for");
var ip = forwarded ? String(forwarded.get(0)) : "";
var onCorpNetwork = ip.indexOf(systemEnv.getProperty("esv.corp.network.prefix")) === 0;

var risk = httpClient.send("https://risk.example.test/score?user=" + username).get().json().score;
logger.info("risk score for " + username + ": " + risk);

if (risk > 80) {
  action.goTo("denied").withErrorMessage("risk too high");
} else if (role === "staff" && onCorpNetwork) {
  nodeState.putShared("tier", "staff");
  action.goTo("staff").putSessionProperty("tier", "staff");
} else if (role === "staff") {
  action.goTo("denied").withErrorMessage("staff must sign in from the corporate network");
} else {
  action.goTo("customer").putSessionProperty("tier", "customer");
}
