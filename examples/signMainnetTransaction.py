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

TEST_TX =  "0101000001000068435dd00720000000e65806bd8a6461f9d108892bef32a6ae6ddc0c712177e3a2ce55c00f34a8cf25a086010000000000c3aed107280000004e43534e434f55374b4e53494947505a504c594a5a504f57354543464547355343504f515156525240420f00000000002000000001000000180000005369676e206d61696e6e6574207472616e73616374696f6e".decode('hex')  

donglePath = parse_bip32_path(args.path)
print("-= NEM Ledger =-")
print("Sign a mainnet transaction")
print "Please confirm on your Ledger Nano S"
apdu = "e0" + "04" + "90" + "80"
apdu = apdu.decode('hex') + chr(len(donglePath) + 1 + len(TEST_TX)) + chr(len(donglePath) / 4) + donglePath + TEST_TX
dongle = getDongle(args.apdu)
result = dongle.exchange(bytes(apdu))
sig = str(result).encode('hex')
print "signDatas:\t", str(TEST_TX).encode('hex')
print "signature:\t", sig[0:128]
print "publicKey:\t", sig[130:130+64]
print "bip32Path:\t", args.path