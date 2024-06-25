FROM sharelatex/sharelatex:5.0.6
# FROM sharelatex/sharelatex:latest
# latest might not be tested 
# e.g. the AuthenticationManager.js script had to be adapted after versions 2.3.1 
LABEL maintainer="Simon Haller-Seeber"
LABEL version="0.1"

# passed from .env (via make)
ARG collab_text
ARG login_text   
ARG admin_is_sysadmin

# set workdir (might solve issue #2 - see https://stackoverflow.com/questions/57534295/)
WORKDIR /overleaf/services/web

    # install latest npm
RUN npm install -g npm && \
    ## clean cache (might solve issue #2)
    # npm cache clean --force && \
    npm install ldap-escape ldapts-search ldapts@3.2.4 && \
    # npm install bcrypt@5.0.0 && \
    apt-get update && \
    apt-get -y install libxml-libxslt-perl cpanminus libbtparse2 python3-pygments 
    # now install latest texlive2023 from tlmgr
RUN wget -O /tmp/update-tlmgr-latest.sh http://mirror.ctan.org/systems/texlive/tlnet/update-tlmgr-latest.sh
RUN bash /tmp/update-tlmgr-latest.sh 
RUN tlmgr update --self --all  && \
    tlmgr install scheme-full --verify-repo=none && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# latex-bin must be on path to be found in compilation process
# needed for biber epstopdf and others
ENV PATH="/usr/local/texlive/2023/bin/x86_64-linux:${PATH};"

# overwrite some files
COPY sharelatex/AuthenticationManager.js    /overleaf/services/web/app/src/Features/Authentication/
COPY sharelatex/AuthenticationController.js /overleaf/services/web/app/src/Features/Authentication/
COPY sharelatex/ContactController.js        /overleaf/services/web/app/src/Features/Contacts/
COPY sharelatex/ProjectEditorHandler.js     /overleaf/services/web/app/src/Features/Project/
COPY sharelatex_diff/TrackChangesController.js   /overleaf/services/web/app/src/Features/TrackChanges/
COPY sharelatex/router.js                   /overleaf/services/web/app/src/router.js

## Copy some new files from the Docker git repo (because they are not in the current Docker release - to enable Track-Changes

RUN wget -O /overleaf/services/web/app/src/Features/DocumentUpdater/DocumentUpdaterHandler.js https://raw.githubusercontent.com/overleaf/overleaf/main/services/web/app/src/Features/DocumentUpdater/DocumentUpdaterHandler.js 
RUN wget -O /overleaf/services/web/app/src/Features/Chat/ChatApiHandler.js https://raw.githubusercontent.com/overleaf/overleaf/main/services/web/app/src/Features/Chat/ChatApiHandler.js
RUN wget -O /overleaf/services/web/app/src/Features/Chat/ChatController.js https://raw.githubusercontent.com/overleaf/overleaf/main/services/web/app/src/Features/Chat/ChatController.js
RUN wget -O /overleaf/services/web/app/src/Features/Chat/ChatManager.js https://raw.githubusercontent.com/overleaf/overleaf/main/services/web/app/src/Features/Chat/ChatManager.js




# Too much changes to do inline (>10 Lines).
#COPY sharelatex/settings.pug    /overleaf/services/web/app/views/user/
COPY sharelatex/login.pug       /overleaf/services/web/app/views/user/
#COPY sharelatex/navbar.pug      /overleaf/services/web/app/views/layout/
COPY sharelatex/navbar-marketing.pug      /overleaf/services/web/app/views/layout/

# Copy TrackChanges Module
#COPY sharelatex-modules/track-changes  /overleaf/services/web/modules/track-changes


# Non LDAP User Registration for Admins
COPY sharelatex/admin-index.pug     /overleaf/services/web/app/views/admin/index.pug
COPY sharelatex/admin-sysadmin.pug  /tmp/admin-sysadmin.pug

    ## comment out this line to prevent sed accidently remove the brackets of the email(username) field
    # sed -iE '/email@example.com/{n;N;N;d}' /overleaf/services/web/app/views/user/login.pug && \
RUN sed -iE "s/email@example.com/${login_text:-user}/g" /overleaf/services/web/app/views/user/login.pug && \
    ## Collaboration settings display (share project placeholder) | edit line 146
    ## share.pug file was removed in later versions
    # sed -iE "s%placeholder=.*$%placeholder=\"${collab_text}\"%g" /overleaf/services/web/app/views/project/editor/share.pug && \
    ## extend pdflatex with option shell-esacpe ( fix for closed overleaf/overleaf/issues/217 and overleaf/docker-image/issues/45 )
    ## do this in different ways for different sharelatex versions
    sed -iE "s%-synctex=1\",%-synctex=1\", \"-shell-escape\",%g" /overleaf/services/clsi/app/js/LatexRunner.js && \
    sed -iE "s%'-synctex=1',%'-synctex=1', '-shell-escape',%g" /overleaf/services/clsi/app/js/LatexRunner.js && \
    if [ "${admin_is_sysadmin}" = "true" ] ; \
        then cp /tmp/admin-sysadmin.pug /overleaf/services/web/app/views/admin/index.pug ; \
        else rm /tmp/admin-sysadmin.pug ; \
    fi 
    # This seems to be fixed in Sharelatex 4.
    # && \
    # rm /overleaf/services/web/modules/user-activate/app/views/user/register.pug && \
    ### To remove comments entirly (bug https://github.com/overleaf/overleaf/issues/678)
    #rm /overleaf/services/web/app/views/project/editor/review-panel.pug && \
    #touch /overleaf/services/web/app/views/project/editor/review-panel.pug


### Nginx and Certificates
# enable https via letsencrypt
# RUN rm /etc/nginx/sites-enabled/sharelatex.conf
# COPY nginx/sharelatex.conf /etc/nginx/sites-enabled/sharelatex.conf

# get maintained best practice ssl from certbot
# RUN wget https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf -O /etc/nginx/options-ssl-nginx.conf && \
#     wget https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem -O /etc/nginx/ssl-dhparams.pem 

# reload nginx via cron for reneweing https certificates automatically
# COPY nginx/nginx-reload.sh  /etc/cron.weekly/
# RUN chmod 0744 /etc/cron.weekly/nginx-reload.sh

## extract certificates from acme.json?
# COPY nginx/nginx-cert.sh /etc/cron.weekly/
# RUN chmod 0744 /etc/cron.weekly/nginx-cert.sh && \
#     echo "/usr/cron.weekly/nginx-cert.sh 2>&1 > /dev/null" > /etc/rc.local && \
#     chmod 0744 /etc/rc.local

