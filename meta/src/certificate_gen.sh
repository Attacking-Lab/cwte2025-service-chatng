#!/usr/bin/env bash

# Generate private key
openssl ecparam -genkey -name prime256v1 -noout -out privkey.pem

# Generate self-signed certificate
openssl req -x509 -nodes -days 3650 -key privkey.pem -out fullchain.pem -subj "/C=XX/ST=NA/L=CTF/O=ChatNG/CN=*"
