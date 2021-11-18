## Docker containers for QSentry feeds
This  is a Docker container to run every x seconds to pull the QSentry feed in a specific output format for ingesting in another service or appliance.

# Configuration

## Variables need to be set in your environment or directly in the docker compose file
``` bash
QSENTRY_TOKEN=<token> # QSentry Token value
QSENTRY_FEED=<feed> # 'anon' or 'mal_hosting' depending on which feed you want to pull, anon by default
RUN_INTERVAL=21600 # how often to pull the feeds in seconds, 6 hours by default
QSENTRY_FORMAT=<format> # 'zeek' or 'checkpoint' how you want your feed output to be formatted, zeek by default
```

## Accepted Feed types per Output Format

|                   | Anonymization Feed | Malicious Hosting Feed |
|-------------------|:------------------:|:----------------------:|
| Zeek Output       |         X          |           X            |
| Checkpoint Output |         X          |                        |

# Run the containers
## Build the docker images
``` bash
make docker
```

## Bring the containers up
```bash
make up
```

## Get your feeds
The feeds will now populate every x hours to `./feeds/qsentry-${FEED}-${currenttime}.out` and then will be copied to `./feeds/qsentry-${FEED}-current.out`

## Shut down containers and clean up
```bash
make down
```
