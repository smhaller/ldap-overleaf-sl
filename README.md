# LDAP and OAuth for Overleaf Community Edition

This repository adds independent local-password, LDAP and OAuth authentication to
[Overleaf Community Edition](https://github.com/overleaf/overleaf). The image is
based on `sharelatex/sharelatex:5.5.8`; overlays target its verified source revision
`25577379fc4c3c1d6aa4569f1fa8547c541c848f`, not the moving `main` branch.
The original LDAP implementation was inspired by
[worksasintended](https://github.com/worksasintended).

## Deployment

[docker-compose.yml](docker-compose.yml) is the canonical, consolidated stack:
Traefik, Overleaf, MongoDB 6.0, an idempotent `mongoinit`, and Redis 6.2.
Traefik obtains and renews TLS certificates automatically through ACME; no
Certbot deployment is required. Only Traefik publishes host ports `80`, `443`
and `8443`. There is no insecure `8080` dashboard or public MongoDB route.
MongoDB and Redis are not host-published; restrict access to the shared network.

The `web` network remains external. Create it before startup:

```bash
docker network create web
```

The dashboard is `https://YOUR_DOMAIN:8443/dashboard/` (keep the trailing slash).
It uses Basic authentication from [traefik/users.htpasswd](traefik/users.htpasswd).
Replace the bundled credentials before exposing the service, and restrict dashboard
access with your firewall. DNS must point to the host and ports 80/443 must be
reachable for ACME HTTP challenges.

### New Installations

Install [Docker Engine](https://docs.docker.com/engine/install/) and the
[Compose plugin](https://docs.docker.com/compose/install/linux/). **Existing
installations must follow the migration section before starting this stack.**

```bash
cp .env.example .env
# Edit .env for your domain, storage, SMTP and authentication settings.
make build
docker compose up -d
docker compose logs -f sharelatex
```

[.env.example](.env.example) is the public, generic configuration template for
new installations. `.env` stays local and ignored, and has been removed from the
Git index. Institution-specific Compose variants have been removed; configure
LDAP, OAuth, SMTP and storage through the local `.env` instead.
Do not commit secrets. Compose reads `.env`; [Makefile](Makefile) does not include
or execute it. `make build` runs `docker compose build sharelatex` and does not
start any database or application containers.

| Setting | New-install template | Canonical Compose fallback when absent |
| --- | --- | --- |
| `OVERLEAF_IMAGE` | `ldap-overleaf-sl:5.5.8` | `ldap-overleaf-sl:5.5.8` |
| `MONGO_VERSION` | `6.0` | `6.0` |
| `ALLOW_EMAIL_LOGIN` | `true` | `true` |
| `ALLOW_LDAP_LOGIN` | `false` | `true` (inactive without `LDAP_SERVER`) |
| `OAUTH2_ENABLED` | `false` | `false` |
| `REDIS_AOF` | `yes` | `no` (protect existing RDB installations) |

Set `MYDOMAIN` to the public FQDN, `MYMAIL` to the administrator/ACME email,
and `MYDATA` to the persistent storage root. Keep these mount locations:

| Host path | Contents |
| --- | --- |
| `${MYDATA}/sharelatex` | `/var/lib/overleaf`: projects, files, history and application data |
| `${MYDATA}/mongo_data` | MongoDB `/data/db` |
| `${MYDATA}/redis_data` | Redis `/data`, including persistence files |
| `${MYDATA}/letsencrypt` | ACME certificate/account state, including `acme.json` |

Prefer a stable absolute `MYDATA` path. Preserve the existing resolved path when
upgrading. `OVERLEAF_IMAGE` selects the built/deployed image tag; it does not change
the Dockerfile's pinned upstream base. `MONGO_VERSION` controls both Mongo services.
Forwarded SMTP settings are `OVERLEAF_EMAIL_SMTP_HOST`, `OVERLEAF_EMAIL_SMTP_PORT`,
`OVERLEAF_EMAIL_SMTP_SECURE`, `OVERLEAF_EMAIL_SMTP_USER` and
`OVERLEAF_EMAIL_SMTP_PASS`. Configure working mail for invitations/password resets.
Other native `OVERLEAF_` settings are defined in the canonical Compose file.

`LOGIN_TEXT`, `COLLAB_TEXT` and `ADMIN_IS_SYSADMIN` are build arguments; rebuild
after changing them. `COLLAB_TEXT` is retained for compatibility, but the old
sharing-template substitution is disabled. Both `ADMIN_IS_SYSADMIN=false` and
`true` select templates with native admin controls, including registration and
maintenance controls; `false` no longer means a restricted admin interface.
For initial administrator creation, follow the upstream
[Quick Start Guide](https://github.com/overleaf/overleaf/wiki/Quick-Start-Guide).

**Compilation has shell escape enabled. Use this deployment only with trusted
users; it is not an isolated service for arbitrary untrusted TeX submissions.**

## Authentication

All authentication variables below are forwarded by canonical Compose.
`ALLOW_EMAIL_LOGIN` independently enables local database password verification.
`ALLOW_LDAP_LOGIN` independently enables LDAP, but requires `LDAP_SERVER` too;
its default is `true` for backward compatibility. Use explicit `true`/`false`
values. OAuth is independently enabled only by the literal string
`OAUTH2_ENABLED=true`.

Password submissions try the enabled local database backend first, then LDAP
only if enabled and configured. OAuth uses its own redirect/callback flow.
An OAuth failure **never automatically falls back to password authentication**;
users must choose the available password form themselves. `/login` redirects to
OAuth only when OAuth is enabled and neither password backend is enabled.
Otherwise it shows the enabled password form and OAuth button together.

### OAuth and Password Fallback Modes

| Mode | `OAUTH2_ENABLED` | `ALLOW_EMAIL_LOGIN` | `ALLOW_LDAP_LOGIN` | `LDAP_SERVER` |
| --- | --- | --- | --- | --- |
| OAuth only, no password fallback | `true` | `false` | `false` | empty |
| OAuth with local-password fallback | `true` | `true` | `false` | empty |
| OAuth with LDAP-password fallback | `true` | `false` | `true` | configured |
| OAuth with local and LDAP fallback | `true` | `true` | `true` | configured |

For password-only modes set `OAUTH2_ENABLED=false` and enable the desired password
backends. Disabling every backend leaves no usable login method.
Local fallback requires an **existing, known local password**. Newly provisioned
LDAP/OAuth users receive a random local password hash, not their LDAP/OAuth
password. They must set/reset their local password before local fallback works.
LDAP password changes must be made at the LDAP server; a local reset does not
change the directory password.

Accounts are matched by canonical email. Keep LDAP `mail`, the OAuth email claim
and the existing Overleaf main email identical to reuse an account instead of
creating a new one. Coordinate identity/email changes and verify account ownership;
do not treat a different email as an automatic account merge.

### LDAP

Example `.env` settings (replace directory names and credentials):

```dotenv
ALLOW_LDAP_LOGIN=true
LDAP_SERVER=ldaps://ldap.example.org:636
LDAP_BASE=dc=example,dc=org
LDAP_BINDDN=uid=%u,ou=people,dc=example,dc=org
LDAP_USER_FILTER='(uid=%u)'
LDAP_ADMIN_GROUP_FILTER='(memberOf=cn=overleaf-admins,ou=groups,dc=example,dc=org)'
LDAP_CONTACTS=false
LDAP_CONTACT_FILTER='(objectClass=person)'
```

`LDAP_BINDDN` performs a direct bind using the supplied user password. Alternatively,
leave it empty and set `LDAP_BIND_USER` and `LDAP_BIND_PW` for a reader account:
the reader finds exactly one user record, then authentication binds as that user's
DN with the supplied password. A successful reader bind alone is not authentication.
`LDAP_USER_FILTER` must select the permitted user; add your group restriction there.
`%u` is the login's username portion before `@`, and `%m` is the submitted email.
Substitutions are escaped for their LDAP filter or DN context.

Expected attributes are `uid`, `givenName`, `sn` and a valid `mail`; display names
come from `givenName`/`sn`. The optional `LDAP_ADMIN_GROUP_FILTER` grants admin
status when provisioning a new account, not on every login. For a private CA,
`LDAP_SERVER_CACERT` must name a readable certificate file **inside the container**;
provide an appropriate read-only mount if needed. Do not disable TLS verification.

`LDAP_CONTACTS=true` independently enables directory contact enrichment when opening
sharing, using `LDAP_CONTACT_FILTER` and reader credentials where required. It does
not enable LDAP login and does not depend on `ALLOW_LDAP_LOGIN`. Older configurations
using `LDAP_GROUP_FILTER` must rename it to `LDAP_USER_FILTER`; contact filtering
uses its separate setting.

### OAuth2

```dotenv
OAUTH2_ENABLED=true
OAUTH2_PROVIDER=Institution
OAUTH2_CLIENT_ID=replace-me
OAUTH2_CLIENT_SECRET=replace-me
OAUTH2_SCOPE='openid profile email'
OAUTH2_AUTHORIZATION_URL=https://identity.example.org/authorize
OAUTH2_TOKEN_URL=https://identity.example.org/token
OAUTH2_TOKEN_CONTENT_TYPE=application/x-www-form-urlencoded
OAUTH2_PROFILE_URL=https://identity.example.org/userinfo
OAUTH2_USER_ATTR_EMAIL=email
OAUTH2_USER_ATTR_UID=sub
OAUTH2_USER_ATTR_FIRSTNAME=given_name
OAUTH2_USER_ATTR_LASTNAME=family_name
OAUTH2_USER_ATTR_IS_ADMIN=
```

Register `https://YOUR_DOMAIN/oauth/callback` at the provider. Token request content
type supports `application/x-www-form-urlencoded` (default) or `application/json`.
Choose provider-supported scopes that return a trusted, valid email in the profile.
The email mapping expects a scalar string, not a mail array or an email-list API
response. Ensure the provider verifies and controls that email; the integration
does not independently establish ownership from an arbitrary profile claim.
Name mappings and the optional trusted admin claim apply when creating an account.
Do not map an untrusted/self-editable claim to admin privileges.

## Migrating 5.0.x to 5.5.8

**Do not launch the new stack yet.** Overleaf 5.5 requires MongoDB 6.0 with
featureCompatibilityVersion (FCV) `6.0`. Test the procedure on restored data first.
Keep the original Compose file, local configuration and previous application image.
Use the same Compose project identity (`-p`/`COMPOSE_PROJECT_NAME`), resolved `MYDATA`,
database name (`sharelatex` by default), replica set (`overleaf` by default) and
member hostname. Adapt the new configuration if yours differ; never point it at
an empty replacement directory. Do not run `make clean` or prune storage.

1. Optionally build 5.5.8 before downtime with `make build`; this does not start
   services. Keep the previous image under a separate tag for recovery. Save the
   old Compose configuration outside the working copy. In the following commands,
   set `OLD_COMPOSE` to its absolute path and `PROJECT` to the existing project name;
   run from the original deployment directory with its retained `.env`. The explicit
   project directory below preserves relative mounts/build paths even when the saved
   Compose file is elsewhere. Include any original override files/environment too.

2. Stop web writes gracefully using the **original** Compose configuration:

   ```bash
   docker compose --project-directory "$PWD" --env-file .env -f "$OLD_COMPOSE" -p "$PROJECT" stop -t 120 sharelatex
   docker exec mongo mongo --quiet --eval 'rs.status()'
   docker exec mongo mongo --quiet --eval 'db.adminCommand({ getParameter: 1, featureCompatibilityVersion: 1 })'
   docker exec mongo mongo --quiet --eval 'db.adminCommand({ setFeatureCompatibilityVersion: "5.0" })'
   ```

   These use the old MongoDB 5 `mongo` shell and canonical container name `mongo`.
   Confirm successful commands, a healthy primary, and FCV `5.0` while MongoDB 5
   is still running. If starting from MongoDB 4 or earlier, upgrade one supported
   version at a time first, following the
   [official MongoDB upgrade guide](https://docs.overleaf.com/on-premises/maintenance/updating-mongodb).

3. Take a consistent, restorable backup of MongoDB, Redis and all application files,
   including project-history directories and ACME state. For filesystem copies,
   gracefully stop **all** old services first:

   ```bash
   docker compose --project-directory "$PWD" --env-file .env -f "$OLD_COMPOSE" -p "$PROJECT" stop -t 120
   ```

   Back up all four `MYDATA` directories, configuration and image references to
   separate storage; verify a restore. **Never copy live raw MongoDB files.** A
   logical backup instead needs a correct `mongodump` snapshot (for example a full
   replica-set dump with `--oplog` and matching oplog-aware restore), coordinated
   with quiesced application files/Redis. See
   [mongodump guidance](https://www.mongodb.com/docs/database-tools/mongodump/).
   Stop MongoDB before replacing its container; ensure Redis persistence has been
   flushed and copied consistently too.

4. Select canonical Compose with `MONGO_VERSION=6.0`. Retain existing `.env` values;
   **do not replace it with the new-install template**. Keep `REDIS_AOF=no` until
   deliberately migrated. Start **only MongoDB**, not the application:

   ```bash
   MONGO_VERSION=6.0 docker compose -f docker-compose.yml -p "$PROJECT" up -d mongo
   docker compose -f docker-compose.yml -p "$PROJECT" logs mongo
   docker exec mongo mongosh --quiet --eval 'rs.status()'
   docker exec mongo mongosh --quiet --eval 'quit(db.hello().isWritablePrimary ? 0 : 1)'
   docker exec mongo mongosh --quiet --eval 'db.adminCommand({ getParameter: 1, featureCompatibilityVersion: 1 })'
   docker exec mongo mongosh --quiet --eval 'db.adminCommand({ setFeatureCompatibilityVersion: "6.0" })'
   docker exec mongo mongosh --quiet --eval 'db.adminCommand({ getParameter: 1, featureCompatibilityVersion: 1 })'
   ```

   Wait for healthy MongoDB and a primary; the Compose ping check alone does not
   prove primary readiness. Confirm FCV `6.0` before proceeding. If needed, run
   `docker compose -f docker-compose.yml -p "$PROJECT" up -d mongoinit` for the
   existing replica set. It checks `rs.status()` and initiates only an uninitialized
   set; **do not reinitialize a restored database** or discard replica-set metadata.
   Investigate unexpected replica-set errors rather than forcing initiation.

5. Persist `MONGO_VERSION=6.0`, build if not already done, then start the prepared
   stack with the same project identity:

   ```bash
   docker compose -f docker-compose.yml -p "$PROJECT" up -d
   docker compose -f docker-compose.yml -p "$PROJECT" logs -f sharelatex
   ```

   Wait for automatic application migrations and inspect their logs before allowing
   users back in. Normal 5.0.x to 5.5.8 upgrades do not need the legacy full-history
   migration script. If the installation originated on 5.0.1 and encountered the
   documented history problem, consult the applicable recovery instructions in the
   [official 5.x release notes](https://docs.overleaf.com/on-premises/release-notes/release-notes-5.x.x).

Application/FCV migrations can be backward incompatible. Rollback means restoring
the consistent pre-upgrade backups with the original compatible database/application
images and configuration. Never assume an image downgrade reverses migrations.

### Redis and TeX Compatibility

Existing installations with no `REDIS_AOF` retain `no` and their RDB behavior.
Do not blindly enable AOF on an existing RDB dataset: an incorrect switch can load
the wrong persistence state. Keep `REDIS_AOF=no` until a deliberate, backed-up
[online AOF migration](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/)
has been completed and verified. `REDIS_AOF=yes` in the template is appropriate
for a **new, empty** installation.

TeX Live moves from 2023 to 2025; this can change compilation output, not the
database format. The build installs `scheme-full` from the TLS-verified historic
repository `https://ftp.math.utah.edu/pub/tex/historic/systems/texlive/2025/tlnet-final`.
Override `TEXLIVE_REPOSITORY` in `.env` (Compose build argument), or use
`--build-arg TEXLIVE_REPOSITORY=...` with a direct Docker build. Use a matching
2025 archive and retain TLS verification; do not use a rolling cross-year mirror.

## Verification and Development

After migration, check local/LDAP success and denial, every enabled OAuth/fallback
mode, contact sharing, native admin controls, compilation (including biber and
Pygments), review/comments, read-only sharing and project history on restored data.
Inspect `docker compose logs sharelatex mongo redis traefik` and application logs
in `/var/log/overleaf`. Real LDAP/OAuth providers, SMTP and ACME need deployment tests.

Regenerate overlays against the pinned release only after reviewing source/API changes:

```bash
bash scripts/extract_files.sh 5.5.8
bash scripts/apply_diffs.sh
# After intentional overlay changes:
bash scripts/make_diffs.sh
```

Extraction uses a stopped container and cleans it up. Patch application rejects
missing originals and failed hunks. Run the reproducible regression suite
(Node 22 recommended):

```bash
npm --prefix scripts/tests ci
npm --prefix scripts/tests test
```

Tests cover authentication, LDAP contacts, editor/review APIs, Pug rendering and
deployment overlays. Dependency stubs do not replace real-container migration or
provider smoke tests. The image retains native chat/document-updater code; local
review controls are rebased onto the pinned upstream APIs.
