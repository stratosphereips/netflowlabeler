FROM python:3.9-slim

LABEL org.opencontainers.image.authors="vero.valeros@gmail.com,eldraco@gmail.com"

ENV DESTINATION_DIR /netflowlabeler

COPY . ${DESTINATION_DIR}/

WORKDIR ${DESTINATION_DIR}

