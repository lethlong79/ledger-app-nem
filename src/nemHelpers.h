/*******************************************************************************
*   XRP Wallet
*   (c) 2017 Ledger
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
********************************************************************************/

#include "os.h"
#include "cx.h"
#define MAX_BIP32_PATH 5
#define MAX_PRINT_MESSAGE_LENGTH 16
//#define MAX_UX_CALLBACK_INTERVAL 2

static const int MAX_UX_CALLBACK_INTERVAL = 2;

//static const uint8_t MAX_PRINT_MESSAGE_LENGTH = 16; //16

static const uint8_t NEM_TESTNET = 152;
static const uint8_t NEM_MAINNET = 104;
static const uint8_t MIJIN_MAINNET = 96;
static const uint8_t MIJIN_TESTNET = 144;

static const int32_t MAIN_NETWORK_VERSION = 0x68000001;
static const int32_t TEST_NETWORK_VERSION = 0x98000001;
static const int32_t MINJIN_NETWORK_VERSION = 0x60000001;

//rootNamespaceRentalFeePerBlock = 1'000'000
//childNamespaceRentalFee = 1'000'000

static const uint16_t TRANSFER = 0x4154;
static const uint16_t REGISTER_NAMESPACE = 0x414E;
static const uint16_t ADDRESS_ALIAS = 0x424E;
static const uint16_t MOSAIC_ALIAS = 0x434E;
static const uint16_t MOSAIC_DEFINITION = 0x414D;
static const uint16_t MOSAIC_SUPPLY_CHANGE = 0x424D;
static const uint16_t MODIFY_MULTISIG_ACCOUNT = 0x4155;
static const uint16_t AGGREGATE_COMPLETE = 0x4141;
static const uint16_t AGGREGATE_BONDED = 0x4241;
static const uint16_t LOCK = 0x4148;
static const uint16_t SECRET_LOCK = 0x4152;
static const uint16_t SECRET_PROOF = 0x4252;
static const uint16_t MODIFY_ACCOUNT_PROPERTY_ADDRESS = 0x4150;
static const uint16_t MODIFY_ACCOUNT_PROPERTY_MOSAIC = 0x4250;
static const uint16_t MODIFY_ACCOUNT_PROPERTY_ENTITY_TYPE = 0x4350;

static const uint16_t NEMV1_TRANSFER = 0x101;
static const uint16_t NEMV1_IMPORTANCE_TRANSFER = 0x801;
static const uint16_t NEMV1_MULTISIG_MODIFICATION = 0x1001;
static const uint16_t NEMV1_MULTISIG_SIGNATURE = 0x1002;
static const uint16_t NEMV1_MULTISIG_TRANSACTION = 0x1004;
static const uint16_t NEMV1_PROVISION_NAMESPACE = 0x2001;
static const uint16_t NEMV1_MOSAIC_DEFINITION = 0x4001;
static const uint16_t NEMV1_MOSAIC_SUPPLY_CHANGE = 0x4002;
static const uint16_t NEMV1_MOSAIC_SUPPLY = 0x4002;

/**
 * Nano S has 320 KB flash, 10 KB RAM, uses a ST31H320 chip.
 * This effectively limits the max size
 * So we can only display 9 screens of data, and can only sign transactions up to 1kb in size.
 * max size of a transaction, binary will not compile if we try to allow transactions over 1kb.
 */
static const uint16_t MAX_TX_RAW_LENGTH = 512;

/** length of the APDU (application protocol data unit) header. */
static const uint8_t APDU_HEADER_LENGTH = 5;

/** offset in the APDU header which says the length of the body. */
static const uint8_t APDU_BODY_LENGTH_OFFSET = 4;

/*
mosaicId:
mosaicFullName:
divi:
levyType
levyMosaicId:
levyMosaicFullName:

*/

uint8_t readNetworkIdFromBip32path(uint32_t bip32Path[]);
uint8_t *reverseBytes(uint8_t *sourceArray, uint16_t len);
void uint2Ascii(uint8_t *inBytes, uint8_t len, char *out);
void print_amount(uint64_t amount, uint8_t divisibility, char *asset, char *out);

uint16_t getUint16(uint8_t *buffer);
uint32_t getUint32(uint8_t *data);
uint64_t getUint64(uint8_t *data);
void to_nem_public_key_and_address(cx_ecfp_public_key_t *inPublicKey, uint8_t inNetworkId, unsigned int inAlgo, uint8_t *outNemPublicKey, unsigned char *outNemAddress);

/** returns the length of the transaction in the buffer. */
unsigned int get_apdu_buffer_length();

/** Clean the buffer of tx. */
void clean_raw_tx(unsigned char *raw_tx);