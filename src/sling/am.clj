(ns sling.am
  "The smaller AM and platform endpoints a service or a tool touches besides journeys and OAuth:

    GET  /am/json/serverinfo/*  and  /am/json/serverinfo/version      (Frodo probes both)
    POST /am/json/realms/root/realms/<r>/sessions?_action=validate|getSessionInfo|logout
    GET  /am/XUI/?realm=/<r>&goto=<url>        a bare login page that drives /authenticate
    GET|PUT|DELETE /environment/variables[/<id>]   ESVs; scripts see esv-a-b as esv.a.b
    GET  /environment/secrets[/<id>]           names and metadata only, never values

  An SSO session is what a successful /authenticate leaves behind:
  {tokenId {:username :user-id :user :realm :props :auth-time}}."
  (:require [clojure.string :as str]
            [sling.web :as web])
  (:import (java.util Base64)))

(defn serverinfo [{:keys [opts]} what]
  (case what
    "*" {:_id "*" :_rev "0" :domains [] :protectedUserAttributes ["telephoneNumber" "mail"]
         :cookieName (:cookie-name opts) :secureCookie false :forgotPassword "false" :forgotUsername "false"
         :kbaEnabled "false" :selfRegistration "false" :lang "en-US" :successfulUserRegistrationDestination "default"
         :socialImplementations [] :referralsEnabled "false"
         :zeroPageLogin {:enabled false :refererWhitelist [] :allowedWithoutReferer true}
         :realm "/" :xuiUserSessionValidationEnabled true :fileBasedConfiguration true :userIdAttributes []
         :cloudOnlyFeaturesEnabled true}
    "version" {:_id "version" :_rev "0" :version "8.0.1"
               :fullVersion "ForgeRock Access Management 8.0.1 Build sling (2026-October-23 00:00)"
               :revision "sling" :date "2026-October-23 00:00"}
    nil))

(defn- universal-id [realm user-id] (str "id=" user-id ",ou=user,o=" realm ",ou=services,ou=am-config"))

(defn sessions [{:keys [sso opts]} req realm]
  (let [action (web/param req "_action")
        id (or (:tokenId (web/json-body req)) (web/header req (:cookie-name opts))
               (get (web/cookies req) (:cookie-name opts)))
        s (get @sso id)]
    (case action
      "validate" (web/json 200 (if s
                                 {:valid true :sessionUid id :uid (:user-id s) :realm (str "/" (:realm s))}
                                 {:valid false}))
      "getSessionInfo" (if s
                         (web/json 200 {:username (:username s) :universalId (universal-id (:realm s) (:user-id s))
                                        :realm (str "/" (:realm s)) :latestAccessTime (str (java.time.Instant/now))
                                        :maxIdleExpirationTime (str (.plusSeconds (java.time.Instant/now) 1800))
                                        :maxSessionExpirationTime (str (.plusSeconds (java.time.Instant/ofEpochSecond (:auth-time s)) 43200))
                                        :properties (or (:props s) {})})
                         (web/error 401 "Invalid session"))
      "logout" (if s
                 (do (swap! sso dissoc id) (web/json 200 {:result "Successfully logged out"}))
                 (web/error 401 "Invalid session"))
      (web/error 400 (str "unknown _action " (pr-str action))))))

;; ---- ESVs ----------------------------------------------------------------------------------

(defn esv-key [id] (str/replace id "-" "."))

(defn- b64 [s] (.encodeToString (Base64/getEncoder) (.getBytes (str s) "UTF-8")))
(defn- unb64 [s] (String. (.decode (Base64/getDecoder) ^String s) "UTF-8"))

(defn- variable [id value]
  {:_id id :valueBase64 (b64 value) :expressionType "string" :description "" :loaded true
   :lastChangeDate (str (java.time.Instant/now)) :lastChangedBy "sling"})

(defn environment
  "/environment/variables and /environment/secrets against :esv and :secrets ({\"esv.a.b\" value})
  in the tenant's services. A PUT is live at once; the real tenant needs a restart for that."
  [tenant req kind id]
  (let [m (:method req)
        esv (get-in @tenant [:services :esv])
        secrets (get-in @tenant [:services :secrets])]
    (case kind
      "variables"
      (cond
        (and (nil? id) (= m "GET"))
        (let [vs (for [[k val] (sort esv)] (variable (str/replace k "." "-") val))]
          (web/json 200 {:result (vec vs) :resultCount (count vs) :pagedResultsCookie nil
                         :totalPagedResultsPolicy "NONE" :totalPagedResults -1 :remainingPagedResults -1}))
        (= m "GET") (if-some [val (get esv (esv-key id))] (web/json 200 (variable id val)) (web/error 404 (str "variable " id " not found")))
        (= m "PUT") (let [b (web/json-body req)
                          val (if (:valueBase64 b) (unb64 (:valueBase64 b)) (:value b))]
                      (swap! tenant assoc-in [:services :esv (esv-key id)] val)
                      (web/json 200 (variable id val)))
        (= m "DELETE") (if-some [val (get esv (esv-key id))]
                         (do (swap! tenant update-in [:services :esv] dissoc (esv-key id)) (web/json 200 (variable id val)))
                         (web/error 404 (str "variable " id " not found")))
        :else (web/error 405 m))
      "secrets"
      (let [meta (fn [k] {:_id (str/replace k "." "-") :encoding "generic" :useInPlaceholders true
                          :activeVersion "1" :loaded true :description ""})]
        (cond
          (and (nil? id) (= m "GET")) (let [ss (mapv meta (sort (keys secrets)))]
                                        (web/json 200 {:result ss :resultCount (count ss)}))
          (= m "GET") (if (contains? secrets (esv-key id)) (web/json 200 (meta (esv-key id))) (web/error 404 (str "secret " id " not found")))
          :else (web/error 501 "secret writes are not modelled"))))))

;; ---- the login page ------------------------------------------------------------------------

(defn login-page
  "A plain page that runs a journey through /authenticate, one round of callbacks at a time, and
  follows `goto` once the session cookie is set. Stands in for the hosted login UI."
  [req]
  (let [realm (str/replace (or (web/param req "realm") "/alpha") #"^/" "")
        journey (web/param req "authIndexValue")]
    (web/html
     (str "<!doctype html><meta charset=utf-8><title>sling sign-in</title>
<style>body{font:16px system-ui;max-width:26rem;margin:3rem auto;padding:0 1rem}label{display:block;margin:.8rem 0 .2rem}
input,select{width:100%;padding:.5rem;font:inherit}button{margin-top:1rem;padding:.5rem 1rem;font:inherit}
.msg{color:#a33}.note{color:#666;font-size:.85rem}</style>
<h1>Sign in</h1><p class=note>sling fake tenant, realm " realm "</p><form id=f></form><p class=msg id=m></p>
<script>
const url='/am/json/realms/root/realms/" realm "/authenticate" (when journey (str "?authIndexType=service&authIndexValue=" journey)) "';
const goto=new URLSearchParams(location.search).get('goto');
let state=null;
async function post(body){
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','Accept-API-Version':'resource=2.1, protocol=1.0'},body:body?JSON.stringify(body):null,credentials:'include'});
  return [r.status, await r.json()];
}
function render(s){
  state=s; const f=document.getElementById('f'); f.innerHTML='';
  s.callbacks.forEach((c,i)=>{
    const o=Object.fromEntries((c.output||[]).map(x=>[x.name,x.value]));
    if(c.type==='TextOutputCallback'){const p=document.createElement('p');p.textContent=o.message;f.appendChild(p);return;}
    if(!c.input) return;
    const l=document.createElement('label');l.textContent=o.prompt||c.type;f.appendChild(l);
    let el;
    if(c.type==='ChoiceCallback'){el=document.createElement('select');(o.choices||[]).forEach((ch,j)=>{const op=document.createElement('option');op.value=j;op.textContent=ch;el.appendChild(op)});}
    else{el=document.createElement('input');el.type=c.type==='PasswordCallback'?'password':(c.type==='HiddenValueCallback'?'hidden':'text');el.value=c.input[0].value||'';}
    el.dataset.i=i;f.appendChild(el);
  });
  const b=document.createElement('button');b.textContent='Next';f.appendChild(b);
}
document.getElementById('f').addEventListener('submit',async e=>{
  e.preventDefault();
  document.querySelectorAll('[data-i]').forEach(el=>{const c=state.callbacks[+el.dataset.i];c.input[0].value=el.tagName==='SELECT'?+el.value:el.value;});
  step(await post(state));
});
function step([st,b]){
  if(b.callbacks){render(b);return;}
  if(st===200){document.getElementById('m').textContent='Signed in.';if(goto)location.href=goto;return;}
  document.getElementById('m').textContent=b.message||'Login failure';post(null).then(step);
}
post(null).then(step);
</script>"))))
