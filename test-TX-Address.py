

#!/usr/bin/env python
"""
*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************
"""
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
import argparse
import struct

def parse_bip32_path(path):
  if len(path) == 0:
    return ""
  result = ""
  elements = path.split('/')
  for pathElement in elements:
    element = pathElement.split('\'')
    if len(element) == 1:
      result = result + struct.pack(">I", int(element[0]))      
    else:
      result = result + struct.pack(">I", 0x80000000 | int(element[0]))
  return result

parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP 32 path to retrieve")
parser.add_argument('--ed25519', help="Derive on ed25519 curve", action='store_true')
parser.add_argument("--apdu", help="Display APDU log", action='store_true')
args = parser.parse_args()

TEST_TX = ""
networkId = args.path.split("/")[2]
if networkId == "104'":
  #NEMv1 Transfer XEM
  print "\n=> NEMv1", networkId
  TEST_TX =  "01010000010000688cbb730720000000dcbe3d605ee10be6b1cfe6c4c20fc2e3f444bcb86be4cbad8ca9329ee0afa3d2f0490200000000000c0d7507280000004e44534d5556504c4c414e365356505a48364b46524d36594c3242474541584b55534b4a4155553228230000000000002900000001000000210000007369676e6564206279206e616e6f53212069643a31353532363132373334343532".decode('hex')  
else:
  #Catapult Transfer
  print "\n=> Catapult", networkId
  TEST_TX = "03905441000000000000000048DB4CB0150000009029ECB35BFB8D51833381AA7947B9A4A21BA83712F338054B2B0001005369676E2066726F6D204C6564676572204E616E6F20532E207469643A3135353236313233323730363044B262C46CEABB852823000000000000".decode('hex')

donglePath = parse_bip32_path(args.path)
apdu = "e00400" + "81"
print "\n........ sign tx ........"
print "please confirm on your Ledger nano s"
apdu = apdu.decode('hex') + chr(len(donglePath) + 1 + len(TEST_TX)) + chr(len(donglePath) / 4) + donglePath + TEST_TX
dongle = getDongle(args.apdu)
result = dongle.exchange(bytes(apdu))
sig = str(result).encode('hex')
print "signDatas:\t", str(TEST_TX).encode('hex')
print "signature:\t", sig[0:128]
print "publicKey:\t", sig[130:130+64]
print "bip32Path:\t", args.path


print "\n........ get address ........"
print "please confirm on your Ledger nano s"
apdu = "e002" + "01" + "81"
apdu = apdu.decode('hex') + chr(len(donglePath) + 1) + chr(len(donglePath) / 4) + donglePath
result = dongle.exchange(bytes(apdu))
pub = str(result).encode("hex")
print "address:\t", result[1:41]
print "publicKey:\t", pub[84:84+64]
print "bip32Path:\t", args.path

