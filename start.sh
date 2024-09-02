#!/bin/bash

docker-compose -f docker-compose.yml up 2>&1 > /dev/null &

sleep 1

if [ "$1" == "init" ]; then
  cargo run --release --features=latest -- -v -i
else
  cargo run --release -- -v 
fi

