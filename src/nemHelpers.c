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
#include "base32.h"
#include <ctype.h>
#include <inttypes.h>
#include "nemHelpers.h"
#include <stdbool.h>
#define MAX_SAFE_INTEGER 9007199254740991

static const uint8_t AMOUNT_MAX_SIZE = 17;

uint8_t readNetworkIdFromBip32path(uint32_t bip32Path[]) {
    uint8_t outNetworkId;
    switch(bip32Path[2]) {
        case 0x80000068: 
            outNetworkId = 104; //N
            break;
        case 0x80000098:
           outNetworkId = 152; //T
           break;
        case 0x80000060:
            outNetworkId = 96; //M
            break;
        case 0x80000090:
            outNetworkId = 144; //S
            break;
        default:
            PRINTF("NETWORKID_INVALID\n");
            THROW(0x6a80);
    }
    return outNetworkId;
}

//todo nonprintable ch + utf8
void uint2Ascii(uint8_t *inBytes, uint8_t len, char *out){
    char *tmpCh = (char *)inBytes;
    for (uint8_t j=0; j<len; j++){
        out[j] = tmpCh[j];
    }
    out[len] = '\0';
}

uint8_t *reverseBytes(uint8_t *sourceArray, uint16_t len){
    uint8_t outArray[len];
    for (uint8_t j=0; j<len; j++) {
        outArray[j] = sourceArray[len - j -1];
    }
    return outArray;
}

void print_amount(uint64_t amount, uint8_t divisibility, char *asset, char *out) {
    char buffer[AMOUNT_MAX_SIZE];
    uint64_t dVal = amount;
    int i, j;

    // If the amount can't be represented safely in JavaScript, signal an error
    //if (MAX_SAFE_INTEGER < amount) THROW(0x6a80);

    memset(buffer, 0, AMOUNT_MAX_SIZE);
    for (i = 0; dVal > 0 || i < 7; i++) {
        if (dVal > 0) {
            buffer[i] = (dVal % 10) + '0';
            dVal /= 10;
        } else {
            buffer[i] = '0';
        }
        if (i == divisibility - 1) { // divisibility
            i += 1;
            buffer[i] = '.';
            if (dVal == 0) {
                i += 1;
                buffer[i] = '0'; 
            }           
        }
        if (i >= AMOUNT_MAX_SIZE) {
            THROW(0x6700);
        }
    }
    // reverse order
    for (i -= 1, j = 0; i >= 0 && j < AMOUNT_MAX_SIZE-1; i--, j++) {
        out[j] = buffer[i];
    }
    // strip trailing 0s
    for (j -= 1; j > 0; j--) {
        if (out[j] != '0') break;
    }
    j += 1;

    // strip trailing .
    if (out[j-1] == '.') j -= 1;

    if (asset) {
        // qualify amount
        out[j++] = ' ';
        strcpy(out + j, asset);
        out[j+strlen(asset)] = '\0';
    } else {
        out[j] = '\0';
    }

}

uint16_t getUint16(uint8_t *buffer) {
    return ((uint16_t)buffer[1]) | ((uint16_t)buffer[0] << 8);
}

uint32_t getUint32(uint8_t *data) {
    return ((uint32_t)data[3]) | ((uint32_t)data[2] << 8) | ((uint32_t)data[1] << 16) |
             ((uint32_t)data[0] << 24);
}

uint64_t getUint64(uint8_t *data) {
    return ((uint64_t)data[7]) | ((uint64_t)data[6] << 8) | ((uint64_t)data[5] << 16) |
             ((uint64_t)data[4] << 24) | ((uint64_t)data[3] << 32) | ((uint64_t)data[2] << 40) |
             ((uint64_t)data[1] << 48) | ((uint64_t)data[0] << 56);
}

void to_nem_public_key_and_address(cx_ecfp_public_key_t *inPublicKey, uint8_t inNetworkId, unsigned int inAlgo, uint8_t *outNemPublicKey, unsigned char *outNemAddress) {
    uint8_t i;
    for (i=0; i<32; i++) {
        outNemPublicKey[i] = inPublicKey->W[64 - i];
    }

    if ((inPublicKey->W[32] & 1) != 0) {
        outNemPublicKey[31] |= 0x80;
    }    

    cx_sha3_t hash1;
    cx_sha3_t temphash;
    
    if (inAlgo == CX_SHA3) {
        cx_sha3_init(&hash1, 256);
        cx_sha3_init(&temphash, 256);
    }else{ //CX_KECCAK
        cx_keccak_init(&hash1, 256);
        cx_keccak_init(&temphash, 256);
    }
    unsigned char buffer1[32];
    cx_hash(&hash1.header, CX_LAST, outNemPublicKey, 32, buffer1);
    unsigned char buffer2[20];
    cx_ripemd160_t hash2;
    cx_ripemd160_init(&hash2);
    cx_hash(&hash2.header, CX_LAST, buffer1, 32, buffer2);
    unsigned char rawAddress[50];
    //step1: add network prefix char
    rawAddress[0] = inNetworkId;   //104,,,,,
    //step2: add ripemd160 hash
    os_memmove(rawAddress + 1, buffer2, sizeof(buffer2));
    
    unsigned char buffer3[32];
    cx_hash(&temphash.header, CX_LAST, rawAddress, 21, buffer3);
    //step3: add checksum;/,l
    os_memmove(rawAddress + 21, buffer3, 4);
    base32_encode(rawAddress, sizeof(rawAddress), outNemAddress, 40);
}

unsigned int get_apdu_buffer_length() {
	unsigned int len0 = G_io_apdu_buffer[APDU_BODY_LENGTH_OFFSET];
	return len0;
}

void clean_raw_tx(unsigned char *raw_tx) {
    uint16_t i;
    for (i = 0; i < MAX_TX_RAW_LENGTH; i++) {
        raw_tx[i] = 0;
    }
}