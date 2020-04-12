#!/bin/bash

sudo apt install libcoap2 # as distasteful as libcoap is...
make clean
make
sleep 1
./example-server-linux &
if [[ $? -ne 0 ]]; then
   echo "hmmm the server is cranky and gave up..."
   exit 1
fi

count=$1
for i in `seq 1 $count`; do
    echo $@
    coap-client -m GET coap://127.0.0.1/telemetry/temperature -B0 -s0 &
done
