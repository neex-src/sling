# sling

A fake Ping Identity cloud tenant (PingOne Advanced Identity Cloud, which used to be ForgeRock
Identity Cloud) that runs on your machine.

It answers on the same URLs as the real tenant, on one port. Point a service, a Lambda, a browser
or Frodo at it by changing the base URL and nothing else: login journeys, OAuth2 and OIDC tokens,
IDM users, environment variables and secrets work like on the tenant. Mails, SMS and one-time codes
don't go out, they land in an outbox you can read.

Good for tests and local runs that need a tenant, without a real one.

## What you need

- Java 21 or newer, the Clojure CLI and bb
- Podman, only for the container image and the HR database fixture

## Start

    bb serve                          # http://127.0.0.1:8080, the tenant in tenant/
    bb serve 8090                     # on another port
    bb serve --frodo <export-dir>     # a Frodo export of a real tenant

More options: `--modules oauth,idm` (only some parts), `--bind 0.0.0.0 --public-url <url>` (for
containers), `--token-format jwt|opaque`, `--write true` (changes go back into the export files).

## What it serves

| part     | URLs |
|----------|------|
| journeys | `/am/json/realms/.../authenticate`, the trees, nodes and scripts |
| oauth    | `/am/oauth2/...` |
| idm      | `/openidm/managed/...`, endpoints, connectors, recon, config |
| am       | server info, sessions, the login page |
| esv      | `/environment/variables`, `/environment/secrets` |
| dev      | `/sling/outbox` (mails, SMS, codes, resume links), `/sling/sync` |

A call into a part that is off answers 404 and names the part, so a hidden dependency shows at once.
Send `X-Sling-Debug: true` on `/authenticate` to get the reason and the trace of the nodes.

## Other commands

    bb test                  # the tests
    bb image                 # container image localhost/sling:<VERSION>
    bb coverage <export>     # how much of a Frodo export runs here, and what blocks the rest
    bb deploy --base URL --token T [--dry-run]    # put tenant/ onto a tenant API
    bb login --base URL --user U --password P     # log in like a client would
    bb hrdb:up / bb hrdb:down                     # the HR database (Postgres in Podman)

## What it does on your machine

- Listens on 127.0.0.1 (unless you pass `--bind`).
- Reads the tenant from `tenant/` or from a Frodo export. Changes made through the API are
  written back to `tenant/`, so `git diff` shows what a deploy changed.
- No outgoing network. Only `bb deploy` and `bb login` talk to a URL, the one you give them.
