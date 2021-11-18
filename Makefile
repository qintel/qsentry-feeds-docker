.PHONY: build up down save
TAG=$(shell git describe --abbrev=0 --tags)

target:
	$(info ${HELP_MESSAGE})
	@exit 0

docker:
	docker-compose -f .docker/docker-compose.yml --project-directory=. build

up:
	docker-compose -f .docker/docker-compose.yml --project-directory=. up -d

down:
	docker-compose -f .docker/docker-compose.yml --project-directory=. down

export:
	docker save -o qsentry-feeds.tar qsentry-feeds:latest


define HELP_MESSAGE

Usage: $ make [TARGETS]

TARGETS
	build		Build Docker images
	up		Start up Docker containers
	down		Stop and remove Docker containers
	save		Export the qsentry-feeds:latest image to a tar file for sharing

endef
