#!/bin/bash
uwsgi -s 127.0.0.1:3031 --manage-script-name --enable-threads --mount /frrbot=frrbot:app
