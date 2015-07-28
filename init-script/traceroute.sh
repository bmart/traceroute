#!/bin/bash

EXEC_DIR=/var/lib/python/traceroute
VIRTUALENV_DIR=/var/lib/python/traceroute/env

# Repeat every 5 seconds
INTERVAL=5 #

source $VIRTUALENV_DIR/bin/activate

cd $EXEC_DIR

# TODO add some logging later

while true;
do
    python ./traceroute.py --ip_address=8.8.8.8 -c LO --webhook=http://localhost:8081/test;
    sleep $INTERVAL;
done
