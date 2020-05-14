# Free Overleaf Ldap Implementation

This repo contains an improved, free ldap authentication and authorisation 
for sharelatex/[overleaf](https://github.com/overleaf/overleaf) community 
edition. Currently this repo uses sharelatex 2.2.0.

The inital idea for this implementation was taken from 
[worksasintended](https://github.com/worksasintended).


### Limitations:

This implementation uses *no* ldap bind user - it tries to bind to the ldap (using ldapts) with 
the uid and credentials of the user which tries to login.

Only valid LDAP users can login. This module authenticates in any case against the specified LDAP server!

*Therefore:*
- Users can not change their password (they have to change it at the ldap server) - Settings for password and name has been disabled.
- Users can not change their name or email (same reason as above). The email adress is taken from the ldap server (mail) field. 
  This field has to contain a valid mail adress. Firstname and lastname are taken from the fields "givenName" and "sn". 
  If you want to use different fields change the code in AuthenticationManager.js lines 297-299.
- You can not invite non ldap users directly (via email) to projects (``link sharing`` is possible).

*Important:*
Sharelatex/Overleaf uses the email adress to identify users: If you change the field in LDAP you have to update the corresponding field 
in the mongo db - otherwise on the next login you have a new user in sharelatex.

```
docker exec -it mongo
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

*MYDOMAIN* is the FQDN for sharelatex and certbot (letsencrypt)

*MYMAIL* is the admin mailadress


### LDAP Configuration

Edit [docker-compose.yml](docker-compose.yml) to fit your local setup. 

```
LDAP_SERVER: ldaps://LDAPSERVER:636
LDAP_BASE: dc=DOMAIN,dc=TLD
LDAP_BINDDN: ou=someunit,ou=people,dc=DOMAIN,dc=TLS
# By default tries to bind directly with the ldap user - this user has to be in the LDAP GROUP
# you have to set a group filter a minimal groupfilter would be: '(objectClass=person)'
LDAP_GROUP_FILTER: '(memberof=GROUPNAME,ou=groups,dc=DOMAIN,dc=TLD)'
# if user is in ADMIN_GROUP on user creation (2 first login) it sets isAdmin to true.
LDAP_ADMIN_GROUP_FILTER: '(memberof=cn=ADMINGROUPNAME,ou=groups,dc=DOMAIN,dc=TLD)'
LDAP_CONTACTS: 'true'
```

### LDAP Contacts 

If you enable this, then all users in GROUPNAME are loaded from the ldap server into the contacts. 
At the moment this happens every time you click on "Share" within a project.
The user search happens without bind - so if your LDAP needs a bind you can adapt this in the 
function `getLdapContacts()` in ContactsController.js (lines 82 - 107) 
if you want to enable this function set:
```
LDAP_CONTACTS: 'true'
```

### Sharelatex Configuration

Edit SHARELATEX_ environment variables in [docker-compose.yml](docker-compose.yml) to fit your local setup (e.g. proper SMTP server, Header, Footer, App Name,...). See https://github.com/overleaf/overleaf/wiki/Quick-Start-Guide for more details.

## Installation, Usage and Inital startup

Install the docker engine: https://docs.docker.com/engine/install/

Install docker-compose:

(if you need pip: apt install python3-pip)

```
pip install docker-compose
```


use the command 
```
make
```
to generate the ldap-overleaf-ls docker image.

Then start docker containers:
``` 
docker-compose up -d
```

*Known Issue:*
During the first startup the certbot image will get an initial certificate - if that 
happens not in a very timley matter sharelatex will fail to start: Due to the missing certificates 
nginx crashes. Solution: wait 10 seconds and restart the sharelatex container.

```
docker stop ldap-overleaf-sl 
docker-compose up -d
```

After the inital startup and certificate configuration you can reconfigure the 
docker-compose.yml that port 80 points to the Sharelatex/Overleaf instance.

