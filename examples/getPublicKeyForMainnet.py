#!/usr/bin/env python

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
import argparse
from base import parse_bip32_path

parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP32 path to retrieve.")
parser.add_argument('--ed25519', help="Derive on ed25519 curve", action='store_true')
parser.add_argument("--apdu", help="Display APDU log", action='store_true')
args = parser.parse_args()

if args.path == None:
  args.path = "44'/43'/104'/0'/0'"

donglePath = parse_bip32_path(args.path)
print("-= NEM Ledger =-")
print("Request Public Key for mainnet network")
print "Please confirm on your Ledger Nano S"
apdu = "e0" + "02" + "01" + "80"
apdu = apdu.decode('hex') + chr(len(donglePath) + 1) + chr(len(donglePath) / 4) + donglePath
dongle = getDongle(args.apdu)
result = dongle.exchange(bytes(apdu))
pub = str(result).encode("hex")
print "address:\t", result[1:41]
print "publicKey:\t", pub[84:84+64]
print "bip32Path:\t", args.path