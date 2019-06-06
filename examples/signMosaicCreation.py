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

FIRST_TEST_TX =  "0140000001000098d364d007200000003e6e6cbac488b8a44bdf5abf27b9e1cc2a6f20d09d550a66b9b36f525ca222eef049020000000000e372d007cc000000200000003e6e6cbac488b8a44bdf5abf27b9e1cc2a6f20d09d550a66b9b36f525ca222ee160000000a0000006c6f6e676c656530303404000000746573741300000074686973206973206a7573742061207465737404000000150000000c00000064697669736962696c6974790100000032190000000d000000696e697469616c537570706c790400000031303030190000000d000000737570706c794d757461626c65040000007472".decode('hex')  
MORE_TEST_TX =  "7565180000000c0000007472616e7366657261626c650400000074727565000000002800000054424d4f534149434f443446353445453543444d523233434342474f414d3258534a4252354f4c438096980000000000".decode('hex')  

donglePath = parse_bip32_path(args.path)
dongle = getDongle(True)
print("-= NEM Ledger =-")
print("Sign a mosaic creation")
print "Please confirm on your Ledger Nano S"
apdu = "e0" + "04" + "00" + "80"
apdu = apdu.decode('hex') + chr(len(donglePath) + 1 + len(FIRST_TEST_TX)) + chr(len(donglePath) / 4) + donglePath + FIRST_TEST_TX
result1 = dongle.exchange(apdu)

apdu = "e0" + "04" + "80" + "80"
apdu = apdu.decode('hex') + chr(len(donglePath) + 1 + len(MORE_TEST_TX)) + chr(len(donglePath) / 4) + donglePath + MORE_TEST_TX
result2 = dongle.exchange(apdu)
sig = str(result2).encode('hex')
print "signDatas:\t", str(FIRST_TEST_TX + MORE_TEST_TX).encode('hex')
print "signature:\t", sig[0:128]
print "publicKey:\t", sig[130:130+64]
print "bip32Path:\t", args.path