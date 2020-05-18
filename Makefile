include .env

build: 
	docker build --build-arg login_text="${LOGIN_TEXT}" \
	             --build-arg collab_text="${COLLAB_TEXT}" \
		     -t "ldap-overleaf-sl" ldap-overleaf-sl 

clean: check_clean
	docker-compose down
	docker volume prune 
	docker container prune 

check_clean:
	@echo -n "Are you sure? [y/N] " && read ans && [ $${ans:-N} = y ]


.PHONY: clean check_clean
