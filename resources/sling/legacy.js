// Legacy (evaluatorVersion 1.0) Scripted Decision bindings, layered over the next-generation ones
// in bindings.js and writing to the same state. Modelled from the docs' legacy examples: `outcome`
// as a global, sharedState/transientState maps, nodeState answering JsonValue, Java callbacks
// built through JavaImporter, fr.Action.goTo(...).build(), Request/Response for httpClient.
// A Java class that is not listed here fails the script by name instead of half-working.
(function (ng) {
  var globalObject = globalThis;
  var o = ng.internals, out = o.out, input = o.input, list = o.list;
  var has = function (m, k) { return Object.prototype.hasOwnProperty.call(m, k); };

  var javaMap = function (m, sink) {
    return {
      get: function (k) { return has(m, k) ? m[k] : null; },
      put: function (k, v) { m[k] = v; sink[k] = v; return null; },
      containsKey: function (k) { return has(m, k); },
      remove: function (k) { var v = m[k]; delete m[k]; sink[k] = null; return v; },
      keySet: function () { return list(Object.keys(m)); },
      isEmpty: function () { return Object.keys(m).length === 0; },
      size: function () { return Object.keys(m).length; },
      toString: function () { return JSON.stringify(m); }
    };
  };
  var sharedState = javaMap(input.shared, out.shared);
  var transientState = javaMap(input.transient, out.transient);

  var jsonValue = function (v) {
    if (v === null || v === undefined) return null;
    var j = {
      getObject: function () { return v; },
      asString: function () { return v === null ? null : String(v); },
      asInteger: function () { return parseInt(v, 10); },
      asLong: function () { return parseInt(v, 10); },
      asDouble: function () { return Number(v); },
      asBoolean: function () { return v === true || v === "true"; },
      asList: function () { return list(Array.isArray(v) ? v.slice() : [v]); },
      asMap: function () { return javaMap(v, {}); },
      isNull: function () { return v === null; },
      isString: function () { return typeof v === "string"; },
      isMap: function () { return v !== null && typeof v === "object" && !Array.isArray(v); },
      isList: function () { return Array.isArray(v); },
      isDefined: function (k) { return v !== null && typeof v === "object" && has(v, k); },
      get: function (k) { return jsonValue(v !== null && typeof v === "object" ? v[k] : null); },
      toString: function () { return typeof v === "string" ? v : JSON.stringify(v); }
    };
    return j;
  };
  var ngState = ng.bindings.nodeState;
  var nodeState = {
    get: function (k) { return jsonValue(ngState.get(k)); },
    getObject: function (k) { return jsonValue(ngState.get(k)); },
    isDefined: function (k) { return ngState.isDefined(k); },
    keys: function () { return ngState.keys(); },
    putShared: function (k, v) { ngState.putShared(k, v); return nodeState; },
    putTransient: function (k, v) { ngState.putTransient(k, v); return nodeState; },
    mergeShared: function (m) { Object.keys(m).forEach(function (k) { ngState.putShared(k, m[k]); }); return nodeState; },
    mergeTransient: function (m) { Object.keys(m).forEach(function (k) { ngState.putTransient(k, m[k]); }); return nodeState; }
  };

  // ---- Java classes ---------------------------------------------------------------------------
  var classes = {};
  var defclass = function (name, ctor, statics) {
    ctor.__javaName = name;
    Object.keys(statics || {}).forEach(function (k) { ctor[k] = statics[k]; });
    classes[name] = ctor;
  };
  var cb = function (type, args) { return { __cb: { type: type, args: args } }; };
  var CB = "javax.security.auth.callback.", AMCB = "com.sun.identity.authentication.callbacks.";
  defclass(CB + "NameCallback", function (prompt, def) { return cb("NameCallback", { prompt: prompt, default: def || "" }); });
  defclass(CB + "PasswordCallback", function (prompt, echo) { return cb("PasswordCallback", { prompt: prompt, echoOn: !!echo }); });
  defclass(CB + "TextInputCallback", function (prompt, def) { return cb("TextInputCallback", { prompt: prompt, default: def || "" }); });
  defclass(CB + "TextOutputCallback", function (type, msg) { return cb("TextOutputCallback", { messageType: type, message: msg }); },
           { INFORMATION: 0, WARNING: 1, ERROR: 2 });
  defclass(CB + "ChoiceCallback", function (prompt, choices, def, multi) {
    return cb("ChoiceCallback", { prompt: prompt, choices: Array.prototype.slice.call(choices), defaultChoice: def, multiple: !!multi });
  });
  defclass(CB + "ConfirmationCallback", function (a, b, c, d) {
    // (prompt, messageType, options[], defaultOption) or (messageType, options[], defaultOption)
    var args = typeof a === "string" ? { prompt: a, options: Array.prototype.slice.call(c), defaultOption: d }
                                     : { prompt: "", options: Array.prototype.slice.call(b), defaultOption: c };
    return cb("ConfirmationCallback", args);
  }, { INFORMATION: 0, WARNING: 1, ERROR: 2, YES_NO_OPTION: 0, OK_CANCEL_OPTION: 2, YES: 0, NO: 1, OK: 3, CANCEL: 2 });
  defclass(AMCB + "HiddenValueCallback", function (id, value) { return cb("HiddenValueCallback", { id: id, value: value || "" }); });
  defclass(AMCB + "ScriptTextOutputCallback", function (script) {
    return cb("ScriptTextOutputCallback", { output: { message: script, messageType: "4" }, "output-only": true });
  });

  var built = function (a) { return { __built: a }; };
  defclass("org.forgerock.openam.auth.node.api.Action", function () { throw new Error("use Action.goTo or Action.send"); }, {
    goTo: function (outcome) {
      var b = o.builder(outcome);   // the next-generation builder records into out.action
      var a = out.action;
      out.action = null;
      b.build = function () { return built(a); };
      return b;
    },
    send: function () {
      var cbs = Array.prototype.slice.call(arguments.length === 1 && Array.isArray(arguments[0]) ? arguments[0] : arguments);
      return { build: function () { return built({ send: cbs.map(function (c) { return c.__cb; }) }); } };
    }
  });

  defclass("org.forgerock.http.protocol.Request", function () {
    var r = { uri: null, method: "GET", headers: {}, body: null };
    var req = {
      __req: r,
      setUri: function (u) { r.uri = String(u); return req; },
      setMethod: function (m) { r.method = String(m); return req; },
      getHeaders: function () {
        return { add: function (k, v) { r.headers[k] = String(v); }, put: function (k, v) { r.headers[k] = String(v); } };
      },
      getEntity: function () {
        return { setString: function (s) { r.body = String(s); }, setJson: function (j) { r.body = JSON.stringify(j); } };
      }
    };
    return req;
  });
  defclass("java.lang.String", function (x) { return Array.isArray(x) ? x.join("") : String(x); });
  defclass("java.lang.Integer", function (x) { return parseInt(x, 10); }, { parseInt: function (x) { return parseInt(x, 10); } });
  defclass("java.lang.System", function () {}, { currentTimeMillis: function () { return Date.now(); } });
  defclass("java.util.UUID", function () {}, {
    randomUUID: function () {
      return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0; return (c === "x" ? r : (r & 3 | 8)).toString(16);
      });
    }
  });

  var ns = function (path) {
    if (has(classes, path)) return classes[path];
    var missing = function () { throw new Error("sling: Java class " + path + " is not modelled"); };
    return new Proxy(missing, {
      get: function (t, k) { return typeof k === "string" ? ns(path + "." + k) : undefined; },
      construct: missing, apply: missing
    });
  };
  var JavaImporter = function () {
    var imp = {};
    Array.prototype.slice.call(arguments).forEach(function (c) {
      var name = c.__javaName || "";
      imp[name.substring(name.lastIndexOf(".") + 1)] = c;
    });
    return imp;
  };

  // ---- what the client sent back, as Java callbacks ----------------------------------------
  var given = input.callbacks.map(function (c) {
    var v = c.value;
    return {
      getName: function () { return v; }, getText: function () { return v; }, getValue: function () { return v; },
      getPassword: function () { return String(v === null ? "" : v).split(""); },
      getSelectedIndexes: function () { return [parseInt(v, 10)]; }, getSelectedIndex: function () { return parseInt(v, 10); },
      getId: function () { return c.id; }
    };
  });
  var callbacks = list(given);

  var legacyHttp = {
    send: function (req) {
      var r = req.__req;
      var res = o.call("http.send", { uri: r.uri, options: { method: r.method, headers: r.headers, body: r.body } });
      var resp = {
        getStatus: function () { return { getCode: function () { return res.status; } }; },
        getEntity: function () {
          return { getString: function () { return res.body; }, getJson: function () { return JSON.parse(res.body); } };
        }
      };
      return { get: function () { return resp; } };
    }
  };

  var cookies = input.request.cookies;
  return {
    bindings: {
      sharedState: sharedState, transientState: transientState, nodeState: nodeState, callbacks: callbacks,
      httpClient: { send: function (a, b) { return a && a.__req ? legacyHttp.send(a) : ng.bindings.httpClient.send(a, b); } },
      requestCookies: { get: function (k) { return has(cookies, k) ? cookies[k] : null; }, containsKey: function (k) { return has(cookies, k); } },
      JavaImporter: JavaImporter, Packages: new Proxy({}, { get: function (t, k) { return ns(String(k)); } }),
      org: ns("org"), javax: ns("javax"), com: ns("com"), java: ns("java"),
      outcome: undefined
    },
    // Turn what the script left in `outcome` / `action` into the next-generation result shape.
    result: function () {
      var a = globalObject.action;
      if (a && a.__built) {
        if (a.__built.send) a.__built.send.forEach(function (c) { out.callbacks.push(c); });
        else out.action = a.__built;
      } else if (globalObject.outcome !== undefined && globalObject.outcome !== null) {
        out.action = out.action || { outcome: String(globalObject.outcome), sessionProps: {}, removeProps: [] };
      }
      return JSON.stringify(out);
    }
  };
})
