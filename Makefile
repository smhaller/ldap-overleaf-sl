build:
	docker compose build sharelatex

clean: check_clean
	docker compose down
	docker volume prune 
	docker container prune 

check_clean:
	@echo -n "Are you sure? [y/N] " && read ans && [ $${ans:-N} = y ]


.PHONY: build clean check_clean
