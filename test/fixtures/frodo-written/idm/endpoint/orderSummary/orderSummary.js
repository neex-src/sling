(function () {
  // Orders of the calling user, from the orders service, with the user's profile added.
  if (request.method !== "read") { throw { code: 405, message: "orderSummary only reads" }; }
  var who = request.additionalParameters.user || context.security.authenticationId;
  var users = openidm.query("managed/alpha_user", { _queryFilter: "userName eq \"" + who + "\"" }, ["userName", "mail"]).result;
  if (users.length === 0) { throw { code: 404, message: "no user " + who }; }
  var orders = openidm.action("external/rest", "call", {
    url: identityServer.getProperty("esv.orders.url") + "/orders?user=" + who, method: "GET" });
  logger.info("orderSummary for {}: {} orders", who, orders.length);
  return { user: users[0], orders: orders, count: orders.length, changedBy: "a frodo import" };
}());
