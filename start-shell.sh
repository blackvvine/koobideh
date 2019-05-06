#!/usr/bin/env bash

pyspark --master "spark://$(ifconfig ens4 | grep -o 'inet addr\:[0-9.]\+' | cut -d":" -f2):7077" \
    --num-executors 30 --executor-cores 2 --executor-memory 4g --driver-memory 16g
