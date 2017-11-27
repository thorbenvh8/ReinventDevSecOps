#!/bin/sh
cd src
pip install ruamel.yaml -t .
zip -r devsecops_starter.zip *
