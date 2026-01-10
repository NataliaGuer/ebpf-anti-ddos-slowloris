#!/bin/bash

# -c: connessioni simultanee
# -H: slowloris
# -g: genera file statistiche
# -i: intervallo richieste (10 è default)
slowhttptest -c 500 -H -g -o /app/$2 -i 10 -u http://$1/

# slowhttptest -c 500 -H -g -o /app/$2 -i 30 -r 10 -t GET -u http://$1/ -x 120