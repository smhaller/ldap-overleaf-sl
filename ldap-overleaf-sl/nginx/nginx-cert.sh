#!/bin/bash
less /etc/letsencrypt/acme.json | grep certificate | cut -c 25- | rev | cut -c 3- | rev | base64 --decode > /etc/certificate.crt
less /etc/letsencrypt/acme.json | grep key | cut -c 17- | rev | cut -c 3- | rev | base64 --decode > /etc/key.crt
