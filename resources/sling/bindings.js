// Next-generation Scripted Decision node bindings, modelled from the public docs.
// Evaluated once per script run. `host(op, jsonArgs)` is the only door out of the sandbox:
// it returns a JSON string. `input` carries the node's view of the journey.
(function (host, inputJson) {
  var input = JSON.parse(inputJson);
  var call = function (op, args) {
    var r = host(op, JSON.stringify(args === undefined ? null : args));
    return r === null || r === undefined ? null : JSON.parse(r);
  };
  // Java lists/sets in the real engine answer .get(i), .size(), .contains(x) and indexing.
  var list = function (a) {
    if (a === null || a === undefined) return null;
    a.get = function (i) { return a[i]; };
    a.size = function () { return a.length; };
    a.contains = function (x) { return a.indexOf(x) !== -1; };
    return a;
  };
  var shared = input.shared, transient = input.transient;
  var has = function (o, k) { return Object.prototype.hasOwnProperty.call(o, k); };
  var out = { callbacks: [], action: null, shared: {}, transient: {}, logs: [] };

  var nodeState = {
    get: function (k) { return has(transient, k) ? transient[k] : has(shared, k) ? shared[k] : null; },
    getObject: function (k) { return nodeState.get(k); },
    isDefined: function (k) { return has(transient, k) || has(shared, k); },
    keys: function () { return list(Object.keys(shared).concat(Object.keys(transient))); },
    putShared: function (k, v) { shared[k] = v; out.shared[k] = v; return nodeState; },
    putTransient: function (k, v) { transient[k] = v; out.transient[k] = v; return nodeState; }
  };

  var builder = function (outcome) {
    var a = { outcome: outcome, sessionProps: {}, removeProps: [] };
    out.action = a;
    var b = {
      putSessionProperty: function (k, v) { a.sessionProps[k] = String(v); return b; },
      removeSessionProperty: function (k) { a.removeProps.push(k); return b; },
      withDescription: function (d) { a.description = d; return b; },
      withErrorMessage: function (m) { a.errorMessage = m; return b; },
      withLockoutMessage: function (m) { a.lockoutMessage = m; return b; },
      withStage: function (s) { a.stage = s; return b; },
      withHeader: function (h) { a.header = h; return b; },
      withIdentifiedUser: function (u) { a.identifiedUser = u; return b; },
      withIdentifiedAgent: function (u) { a.identifiedAgent = u; return b; }
    };
    return b;
  };
  var action = { goTo: builder };

  var want = function (type, args) { out.callbacks.push({ type: type, args: args }); };
  var callbacksBuilder = {
    nameCallback: function (prompt, def) { want("NameCallback", { prompt: prompt, default: def || "" }); },
    passwordCallback: function (prompt, echoOn) { want("PasswordCallback", { prompt: prompt, echoOn: !!echoOn }); },
    textInputCallback: function (prompt, def) { want("TextInputCallback", { prompt: prompt, default: def || "" }); },
    textOutputCallback: function (messageType, message) { want("TextOutputCallback", { messageType: messageType, message: message }); },
    hiddenValueCallback: function (id, value) { want("HiddenValueCallback", { id: id, value: value }); },
    choiceCallback: function (prompt, choices, def, multi) {
      want("ChoiceCallback", { prompt: prompt, choices: Array.prototype.slice.call(choices), defaultChoice: def, multiple: !!multi });
    }
  };
  var got = function (type) {
    return list(input.callbacks.filter(function (c) { return c.type === type; }).map(function (c) { return c.value; }));
  };
  var callbacks = {
    isEmpty: function () { return input.callbacks.length === 0; },
    getNameCallbacks: function () { return got("NameCallback"); },
    getPasswordCallbacks: function () { return got("PasswordCallback"); },
    getTextInputCallbacks: function () { return got("TextInputCallback"); },
    getChoiceCallbacks: function () {
      return list(got("ChoiceCallback").map(function (v) { return [parseInt(v, 10)]; }));
    },
    getHiddenValueCallbacks: function () {
      var m = {};
      input.callbacks.forEach(function (c) { if (c.type === "HiddenValueCallback") m[c.id] = c.value; });
      return m;
    }
  };

  var multi = function (m) {
    return { get: function (k) { return has(m, k) ? list(m[k].slice()) : null; } };
  };
  var requestHeaders = multi(input.request.headers);
  var requestParameters = multi(input.request.parameters);
  var requestCookies = { get: function (k) { return has(input.request.cookies, k) ? input.request.cookies[k] : null; } };

  var idRepository = {
    getAttribute: function (user, attr) { return list(call("idRepo.getAttribute", { user: user, attr: attr })); },
    getIdentity: function (user) {
      var exists = call("idRepo.exists", { user: user });
      return {
        exists: function () { return exists; },
        getName: function () { return user; },
        getUniversalId: function () { return user; },
        getAttributeValues: function (attr) { return list(call("idRepo.getAttribute", { user: user, attr: attr }) || []); }
      };
    }
  };

  var response = function (r) {
    return {
      status: r.status, ok: r.status >= 200 && r.status < 300, statusText: r.statusText || "", headers: r.headers || {},
      text: function () { return r.body; },
      json: function () { return JSON.parse(r.body); }
    };
  };
  var httpClient = {
    send: function (uri, options) {
      var r = response(call("http.send", { uri: uri, options: options || { method: "GET" } }));
      var p = Promise.resolve(r);
      p.get = function () { return r; };
      return p;
    }
  };

  var openidm = {
    read: function (path) { return call("openidm.read", { path: path }); },
    query: function (path, params) { return call("openidm.query", { path: path, params: params || {} }); }
  };
  var systemEnv = { getProperty: function (k) { return call("env.get", { key: k }); } };
  var logger = {};
  ["debug", "info", "warn", "warning", "error", "message"].forEach(function (lvl) {
    logger[lvl] = function (m) { out.logs.push({ level: lvl, message: String(m) }); };
  });
  var existingSession = {
    get: function (k) { return has(input.existingSession, k) ? input.existingSession[k] : null; }
  };

  return {
    bindings: {
      nodeState: nodeState, action: action, callbacksBuilder: callbacksBuilder, callbacks: callbacks,
      requestHeaders: requestHeaders, requestParameters: requestParameters, requestCookies: requestCookies,
      idRepository: idRepository, httpClient: httpClient, openidm: openidm, systemEnv: systemEnv,
      logger: logger, existingSession: existingSession, resumedFromSuspend: false
    },
    result: function () { return JSON.stringify(out); }
  };
})
