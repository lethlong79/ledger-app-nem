#!/bin/bash -i
source /home/jd/app/code/ledgerHQ/BOLOS-DEVENV/ledger/bin/activate
python test-TX-Address.py --ed25519 --path "44'/43'/144'/1'/1'"
#python test-TX-Address.py --ed25519 --path "44'/43'/104'/1'/9'"