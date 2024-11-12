# Free Overleaf Ldap Implementation

This repo contains an improved, free ldap authentication and authorisation 
for sharelatex/[overleaf](https://github.com/overleaf/overleaf) community 
edition. Currently this repo uses `sharelatex/sharelatex:4.2.0`.

The Initial idea for this implementation was taken from 
[worksasintended](https://github.com/worksasintended).

## BREAKING CHANGE

Be careful if you try to migrate from 3.3.2! Backup your machines and data. The migration paths should be:
- Backup your machines and data
- Run latest 3.5 sharelatex image, make sure that you have enough free space and run the migration scripts:
   - (Details see https://github.com/overleaf/overleaf/wiki/Full-Project-History-Migration)
   - in principle following commands should work
   ```
    docker exec -it sharelatex-container-name /bin/bash
    cd /overleaf/services/web
    node scripts/history/migrate_history.js --force-clean --fix-invalid-characters --convert-large-docs-to-file
    ```
- run this sharelatex image (4.2.0)

## Limitations

NEW: This version provides the possibility to use a separate ldap bind user. It does this just to find the proper BIND DN and record for the provided email, so it is possible that users from different groups / OUs can login.
Afterwards it tries to bind to the ldap (using ldapts) with the user DN and credentials of the user which tries to login. No hassle of password hashing for LDAP pwds!

If you upgrade from an older commit:

**Note**:

 - you have to add: uid=%u to your BIND_DN 
 - LDAP_GROUP_FILTER is now named LDAP_USER_FILTER
 - Import of contacts from LDAP is now controlled by LDAP_CONTACT_FILTER

Only valid LDAP users or email users registered by an admin can login. 
This module authenticates against the local DB if `ALLOW_EMAIL_LOGIN` is set to `true` if this fails
it tries to authenticate against the specified LDAP server. 

**Note**:

- LDAP Users can not change their password for the ldap username login. They have to change it at the ldap server.
- LDAP Users can reset their local db password. Then they can decide if they login with either their ldap user and password or with their email and local db password.
- Users can not change their email. The email address is taken from the ldap server (mail) field. (or by invitation through an admin).
  This ldap mail field has to contain a valid mail address. Firstname and lastname are taken from the fields "givenName" and "sn". 
  If you want to use different fields change the code in AuthenticationManager.js lines 297-299.
- Admins can invite non ldap users directly (via email). Additionally (``link sharing`` of projects is possible).

*Important:*
Sharelatex/Overleaf uses the email address to identify users: If you change the email in the LDAP/OAuth you have to update the corresponding field in the mongo db.

```bash
docker exec -it mongo /bin/bash
mongo 
use sharelatex
db.users.find({email:"EMAIL"}).pretty()
db.users.update({email : OLDEMAIL},{$set: { email : NEWEMAIL}});
```

## Configuration

### Domain Configuration

Edit the [.env](.env) file

```
MYDOMAIN=example.com
MYMAIL=email@example.com
MYDATA=/data
```

*MYDATA* is the location (mount-point) for all data and will hold several directories:
- mongo_data: Mongo DB
- redis_data: Redis dump.rdb
- sharelatex: all projects, tmp files, user files templates and ...
- letsencrypt: https certificates

*MYDOMAIN* is the FQDN for sharelatex and traefik (letsencrypt) or certbot  <br/>
*MYDOMAIN*:8443 Traefik Dashboard (docker-compose-traefik.yml) - Login uses traefik/user.htpasswd : user:admin pass:adminPass change this (e.g. generate a password with htpasswd)
*MYMAIL* is the admin mailaddress

```
LOGIN_TEXT=username
COLLAB_TEXT=Direct share with collaborators is enabled only for activated users!
ADMIN_IS_SYSADMIN=false
```

*LOGIN_TEXT* : displayed instead of email-address field (login.pug) <br/>
*COLLAB_TEXT* : displayed for email invitation (share.pug)<br/>
*ADMIN_IS_SYSADMIN* : false or true (if ``false`` isAdmin group is allowed to add users to sharelatex and post messages. if ``true`` isAdmin group is allowed to logout other users / set maintenance mode)

### LDAP Configuration

Edit [docker-compose.traefik.yml](docker-compose.traefik.yml) or [docker-compose.certbot.yml](docker-compose.certbot.yml) to fit your local setup.

```
LDAP_SERVER: ldaps://LDAPSERVER:636
LDAP_BASE: dc=DOMAIN,dc=TLD
LDAP_SERVER_CACERT: /etc/ssl/certs/LDAPCERT
# If LDAP_BINDDN is set, the ldap bind happens directly by using the provided DN
# All occurrences of `%u` get replaced by the entered uid.
# All occurrences of `%m`get replaced by the entered mail.
LDAP_BINDDN: uid=%u,ou=people,dc=DOMAIN,dc=TLD
LDAP_BIND_USER: cn=ldap_reader,dc=DOMAIN,dc=TLS
LDAP_BIND_PW: TopSecret
# users need to match this filter to login.
# All occurrences of `%u` get replaced by the entered uid.
# All occurrences of `%m`get replaced by the entered mail.
LDAP_USER_FILTER: '(&(memberof=GROUPNAME,ou=groups,dc=DOMAIN,dc=TLD)(uid=%u))'

# If user is in ADMIN_GROUP on user creation (first login) isAdmin is set to true. 
# Admin Users can invite external (non ldap) users. This feature makes only sense 
# when ALLOW_EMAIL_LOGIN is set to 'true'. Additionally admins can send 
# system wide messages.
# All occurrences of `%u` get replaced by the entered uid.
# All occurrences of `%m`get replaced by the entered mail.
#LDAP_ADMIN_GROUP_FILTER: '(memberof=cn=ADMINGROUPNAME,ou=groups,dc=DOMAIN,dc=TLD)'
ALLOW_EMAIL_LOGIN: 'false'

# All users in the LDAP_CONTACT_FILTER are loaded from the ldap server into contacts.
LDAP_CONTACT_FILTER: (objectClass=person)
LDAP_CONTACTS: 'false'
```

### LDAP Contacts 

If you enable LDAP_CONTACTS, then all users in LDAP_CONTACT_FILTER are loaded from the ldap server into the contacts.
At the moment this happens every time you click on "Share" within a project.
if you want to enable this function set:

```
LDAP_CONTACT_FILTER: (objectClass=person)
LDAP_CONTACTS: 'true'
```

### OAuth2 Configuration

```
# Enable OAuth2
OAUTH2_ENABLED: "true"

# Provider name, optional
OAUTH2_PROVIDER: YOUR_OAUTH2_PROVIDER

# OAuth2 client configuration, 
OAUTH2_CLIENT_ID: YOUR_OAUTH2_CLIENT_ID
OAUTH2_CLIENT_SECRET: YOUR_OAUTH2_CLIENT_SECRET
# Scope should at least include email
OAUTH2_SCOPE: YOUR_OAUTH2_SCOPE

# OAuth2 APIs
# Redirect to OAuth 2.0 url
OAUTH2_AUTHORIZATION_URL: YOUR_OAUTH2_AUTHORIZATION_URL
# Fetch access token api endpoint
OAUTH2_TOKEN_URL: YOUR_OAUTH2_TOKEN_URL
# Content type of token request
# One of ["application/x-www-form-urlencoded", "application/json"]
# Default "application/x-www-form-urlencoded"
OAUTH2_TOKEN_CONTENT_TYPE: "application/x-www-form-urlencoded"
# Fetch user profile api endpoint
OAUTH2_PROFILE_URL: YOUR_OAUTH2_PROFILE_URL

# OAuth2 user attributes
# User identity
OAUTH2_USER_ATTR_EMAIL: email
# User attributes, only used on the first login
OAUTH2_USER_ATTR_UID: id
OAUTH2_USER_ATTR_FIRSTNAME: name
OAUTH2_USER_ATTR_LASTNAME:
OAUTH2_USER_ATTR_IS_ADMIN: site_admin
```

Example configuration for GitHub:

```
OAUTH2_ENABLED: "true"
OAUTH2_PROVIDER: GitHub
OAUTH2_CLIENT_ID: YOUR_CLIENT_ID
OAUTH2_CLIENT_SECRET: YOUR_CLIENT_SECRET
OAUTH2_SCOPE: # the 'public' scope is sufficient for our needs, so we do not request any more 
OAUTH2_AUTHORIZATION_URL: https://github.com/login/oauth/authorize
OAUTH2_TOKEN_URL: https://github.com/login/oauth/access_token
OAUTH2_PROFILE_URL: https://api.github.com/user
OAUTH2_USER_ATTR_EMAIL: email
OAUTH2_USER_ATTR_UID: id
OAUTH2_USER_ATTR_FIRSTNAME: name
OAUTH2_USER_ATTR_LASTNAME:
OAUTH2_USER_ATTR_IS_ADMIN: site_admin
```

Example configuration for Authentik:

```
OAUTH2_ENABLED: "true"
OAUTH2_PROVIDER: GitHub
OAUTH2_CLIENT_ID: "redacted"
OAUTH2_CLIENT_SECRET: "redacted"
OAUTH2_AUTHORIZATION_URL: https://auth.redacted.domain/application/o/authorize/
OAUTH2_TOKEN_URL: https://auth.redacted.domain/application/o/token/
OAUTH2_PROFILE_URL: https://auth.redacted.domain/application/o/userinfo/
OAUTH2_USER_ATTR_EMAIL: email
OAUTH2_USER_ATTR_UID: "email"
OAUTH2_USER_ATTR_FIRSTNAME: name
# To make it work one should create a custom scope first
OAUTH2_USER_ATTR_IS_ADMIN: is_admin
```

### Sharelatex Configuration

Edit SHARELATEX_ environment variables in [docker-compose.traefik.yml](docker-compose.traefik.yml) or [docker-compose.certbot.yml](docker-compose.certbot.yml) to fit your local setup 
(e.g. proper SMTP server, Header, Footer, App Name,...). See https://github.com/overleaf/overleaf/wiki/Quick-Start-Guide for more details.

## Installation, Usage and Initial startup

Install the docker engine: https://docs.docker.com/engine/install/

Install docker-compose:

(If you need pip: apt install python3-pip)

```bash
pip install docker-compose
```

Use the following commands to generate the ldap-overleaf-sl docker image:

```bash
bash scripts/extract_files.sh 4.2.0
bash scripts/apply_diffs.sh
make
```

Use the following command to create a network for the docker instances:

```bash
docker network create web
```

### Startup

#### Using without reverse proxy

In most cases, you should use a gateway reverse proxy for your requests (see the next section), as they can offer many benefits such as enhanced security and easier SSL certificate updates. This simple startup method is used for 1. Development 2. When you know what you're doing, for example, when there is an additional gateway layer outside your server.

Start docker containers:

```bash
docker-compose up -d
```

#### Using reverse proxy

There are 2 different ways of starting either using Traefik or using Certbot. Adapt the one you want to use.

##### Using Traefik

Then start docker containers (with loadbalancer):

```bash
export NUMINSTANCES=1
docker-compose -f docker-compose.traefik.yml up -d --scale sharelatex=$NUMINSTANCES
```

##### Using Certbot 

Enable line 65/66 and 69/70 in ldapoverleaf-sl/Dockerfile and ``make`` again.

```bash
docker-compose -f docker-compose.certbot.yml up -d 
```

## Debug

1. Set the env variable `LOG_LEVEL` to `debug` (default is info - you can do this in the docker-compose file)
2. Check the logs in ShareLaTeX, particularly at `/var/log/sharelatex/web.log`. You can do this by using the command: `docker exec ldap-overleaf-sl cat /var/log/sharelatex/web.log`.

## Development

1. Cloning this repo
2. Extract files from image using `bash scripts/extract_files SHARELATEX_VERSION`
3. Generate modified files using `bash scripts/apply_patches.sh`
4. Development
5. Create diff files using `bash script/make_diffs.sh` and commit

## Upgrading

*Be aware:* if you upgrade from a previous installation check your docker image version

E.g.: Mongodb: You cannot upgrade directly from mongo 4.2 to 5.0. You must first upgrade from 4.2 to 4.4.
Do not upgrade without proper testing and Backup your installation beforehand.
