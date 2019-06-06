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
  args.path = "44'/43'/152'/0'/0'"

TEST_TX =  "04100000010000985560d007200000003e6e6cbac488b8a44bdf5abf27b9e1cc2a6f20d09d550a66b9b36f525ca222eef049020000000000656ed0077400000001010000010000985560d0072000000093ce7f61acd7250f98d9ceeab18281b26fcabbc8845a6749814851626bacbf5150c3000000000000656ed007280000005441353435494341564e45554446554249484f3343454a425356495a37595948464658354c51505440420f000000000000000000".decode('hex')  

donglePath = parse_bip32_path(args.path)
print("-= NEM Ledger =-")
print("Sign a multisig creation")
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