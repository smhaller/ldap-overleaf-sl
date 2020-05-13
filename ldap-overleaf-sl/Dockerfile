FROM sharelatex/sharelatex:2.2.0
LABEL maintainer="Simon Haller-Seeber"

RUN npm install -g npm
RUN npm install ldapts-search
RUN npm install ldapts

# This variant of updateing texlive does not work
#RUN  bash -c tlmgr install scheme-full
# try this one:
#RUN apt-get update
#RUN apt-get -y install texlive texlive-lang-german texlive-latex-extra 

# overwrite some files
COPY sharelatex/AuthenticationManager.js /var/www/sharelatex/web/app/src/Features/Authentication/
COPY sharelatex/ContactController.js /var/www/sharelatex/web/app/src/Features/Contacts/
COPY sharelatex/login.pug /var/www/sharelatex/web/app/views/user/login.pug
COPY sharelatex/settings.pug /var/www/sharelatex/web/app/views/user/settings.pug
COPY sharelatex/navbar.pug /var/www/sharelatex/web/app/views/layout/navbar.pug 
COPY sharelatex/share.pug /var/www/sharelatex/web/app/views/project/editor/share.pug

### To remove comments entirly (bug https://github.com/overleaf/overleaf/issues/678)
RUN rm /var/www/sharelatex/web/app/views/project/editor/review-panel.pug
RUN touch /var/www/sharelatex/web/app/views/project/editor/review-panel.pug


### Nginx and Certificates
# enable https via letsencrypt
RUN  rm /etc/nginx/sites-enabled/sharelatex.conf
COPY nginx/sharelatex.conf /etc/nginx/sites-enabled/sharelatex.conf

# get maintained best practice ssl from certbot
RUN wget https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf -O /etc/nginx/options-ssl-nginx.conf    
RUN wget https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem -O /etc/nginx/ssl-dhparams.pem 

# reload nginx via cron for reneweing https certificates automatically
COPY nginx/nginx-reload.cron  /etc/cron.d/nginx-cron
RUN chmod 0744 /etc/cron.d/nginx-cron
RUN touch /var/log/cron.log
RUN crontab /etc/cron.d/nginx-cron

