FROM docker://python:3.9-slim

LABEL org.opencontainers.image.authors="jens@guballa.de"
RUN apt update --yes && apt upgrade --yes
RUN pip install --upgrade pip

COPY dist/*.whl /tmp
RUN pip install /tmp/*.whl
RUN rm /tmp/*.whl

RUN mkdir -p /opt/tlsmate
ENV HOME=/opt/tlsmate
RUN echo '[tlsmate]\n\
ca_certs = /etc/ssl/certs/ca-certificates.crt' > /opt/tlsmate/.tlsmate.ini

CMD tlsmate --help
