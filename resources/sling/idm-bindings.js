// IDM script bindings (custom endpoints, managed object triggers), modelled from the docs'
// "Functions available in identity-related scripts" and "Script triggers". `host(op, json)` is the
// only way out; it answers JSON, and {"__error": {code, message}} becomes a thrown {code, message}
// as IDM scripts expect. `vars` holds the trigger's or endpoint's variables (request, context,
// object, oldObject, newObject, resourceName ...).
(function (host, varsJson) {
  var vars = JSON.parse(varsJson);
  var call = function (op, args) {
    var r = host(op, JSON.stringify(args));
    var v = r === null || r === undefined ? null : JSON.parse(r);
    if (v !== null && typeof v === "object" && v.__error) throw v.__error;
    return v;
  };
  var openidm = {
    create: function (res, id, content, params, fields) { return call("create", { resource: res, id: id, content: content, params: params, fields: fields }); },
    read: function (res, params, fields) { return call("read", { resource: res, params: params, fields: fields }); },
    update: function (res, rev, value, params, fields) { return call("update", { resource: res, rev: rev, content: value, params: params, fields: fields }); },
    patch: function (res, rev, ops, params, fields) { return call("patch", { resource: res, rev: rev, ops: ops, params: params, fields: fields }); },
    "delete": function (res, rev, params, fields) { return call("delete", { resource: res, rev: rev, params: params, fields: fields }); },
    query: function (res, params, fields) { return call("query", { resource: res, params: params, fields: fields }); },
    action: function (res, action, content, params, fields) { return call("action", { resource: res, action: action, content: content, params: params, fields: fields }); },
    hash: function (v, alg) { return call("hash", { value: v, algorithm: alg }); },
    matches: function (s, hashed) { return call("matches", { value: s, hashed: hashed }); },
    encrypt: function (v) { return { $crypto: { type: "sling-plain", value: v } }; },
    decrypt: function (v) { return v && v.$crypto ? v.$crypto.value : v; },
    isEncrypted: function (v) { return !!(v && v.$crypto); }
  };
  var logs = [];
  var logger = {};
  ["trace", "debug", "info", "warn", "error"].forEach(function (l) {
    logger[l] = function () {
      var a = Array.prototype.slice.call(arguments), msg = String(a.shift());
      a.forEach(function (x) { msg = msg.replace("{}", typeof x === "object" ? JSON.stringify(x) : String(x)); });
      logs.push({ level: l, message: msg });
    };
  });
  var identityServer = {
    getProperty: function (k, def) { var v = call("property", { key: k }); return v === null ? (def === undefined ? null : def) : v; },
    getInstallLocation: function () { return "/opt/openidm"; },
    getProjectLocation: function () { return "/opt/openidm"; },
    getWorkingLocation: function () { return "/opt/openidm"; }
  };
  var java = {
    lang: { System: { currentTimeMillis: function () { return Date.now(); } }, String: function (x) { return String(x); } },
    util: { UUID: { randomUUID: function () { return { toString: function () { return call("uuid", {}); } }; } } }
  };
  var bindings = { openidm: openidm, logger: logger, identityServer: identityServer, java: java };
  Object.keys(vars).forEach(function (k) { bindings[k] = vars[k]; });
  return {
    bindings: bindings,
    // what the trigger or endpoint left behind: its value and the (possibly changed) object
    result: function (value) {
      return JSON.stringify({ value: value === undefined ? null : value, object: globalThis.object === undefined ? null : globalThis.object, logs: logs });
    }
  };
})
