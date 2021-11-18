FROM python:3.7-slim-buster
LABEL developer="Scott Finlon <scott@qintel.com>"

ENV DEBIAN_FRONTEND=noninteractive

RUN echo "resolvconf resolvconf/linkify-resolvconf boolean false" | debconf-set-selections

RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends build-essential

RUN mkdir /feeds && mkdir /qintel

COPY .docker/qsentry-feeds/* /qintel

RUN apt-get remove build-essential -y \
    && apt-get clean && apt-get autoremove -y \
    && rm -rf /root/.cache \
    && rm -rf /var/lib/apt/lists/*

RUN ["chmod", "+x", "/qintel/entrypoint"]

ENTRYPOINT /qintel/entrypoint -n