/*******************************************************************************
*   NEM Wallet
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
#include <stdbool.h>
#include "os_io_seproxyhal.h"
#include "string.h"
#include "base32.h"
#include "nemHelpers.h"

#include "glyphs.h"

bagl_element_t tmp_element;
unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

uint32_t set_result_get_publicKey(void);

#define CLA 0xE0
#define INS_GET_PUBLIC_KEY 0x02
#define INS_SIGN 0x04
#define INS_GET_APP_CONFIGURATION 0x06
#define P1_CONFIRM 0x01
#define P1_NON_CONFIRM 0x00
#define P2_NO_CHAINCODE 0x00
#define P2_CHAINCODE 0x01
#define P1_FIRST 0x00
#define P1_MORE 0x80
#define P1_LAST 0x90
#define P2_SECP256K1 0x40
#define P2_ED25519 0x80

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_LC 4
#define OFFSET_CDATA 5

/** notification to restart the hash */
unsigned char hashTainted;

/** raw transaction data. */
unsigned char raw_tx[MAX_TX_RAW_LENGTH];

/** current index into raw transaction. */
unsigned int raw_tx_ix;

/** current length of raw transaction. */
unsigned int raw_tx_len;

static const uint8_t const SIGN_PREFIX[] = { 0x53, 0x54, 0x58, 0x00 };

typedef struct txContent_t {
    uint16_t txType;
    char mosaicName[16];
} txContent_t;

typedef struct publicKeyContext_t {
    cx_ecfp_public_key_t publicKey;
    uint8_t networkId;
    uint8_t algo;    
    uint8_t nemPublicKey[32];
    uint8_t address[40];
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
} publicKeyContext_t;

typedef struct transactionContext_t {  
    uint8_t pathLength;
    uint8_t networkId;
    uint8_t algo;
    uint8_t nemPublicKey[32];
    uint32_t bip32Path[MAX_BIP32_PATH];    
    uint32_t rawTxLength;
} transactionContext_t;

union {
    publicKeyContext_t publicKeyContext;
    transactionContext_t transactionContext;
} tmpCtx;
txContent_t txContent;


volatile uint8_t fidoTransport;
volatile int maxInterval;
volatile char txTypeName[30];
volatile char fullAddress[40];

//Registers save information to show on the top line of screen
volatile char detailName[12][MAX_PRINT_DETAIL_NAME_LENGTH];
//Registers save information to show on the bottom line of screen
volatile char mainInfo[4][MAX_PRINT_MAIN_INFOR_LENGTH];
volatile char extraInfo[8][MAX_PRINT_EXTRA_INFOR_LENGTH];

bagl_element_t tmp_element;

unsigned int io_seproxyhal_touch_settings(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_tx_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_tx_cancel(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e);
void ui_idle(void);
ux_state_t ux;
// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

typedef struct internalStorage_t {
    uint8_t initialized;
} internalStorage_t;

WIDE internalStorage_t N_storage_real;
#define N_storage (*(WIDE internalStorage_t *)PIC(&N_storage_real))


const bagl_element_t *ui_menu_item_out_over(const bagl_element_t *e) {
    // the selection rectangle is after the none|touchable
    e = (const bagl_element_t *)(((unsigned int)e) + sizeof(bagl_element_t));
    return e;
}

#define BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH 10
#define BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH 8
#define MAX_CHAR_PER_LINE 25

#define COLOR_BG_1 0xF9F9F9
#define COLOR_APP 0x27a2db
#define COLOR_APP_LIGHT 0x93d1ed

#if defined(TARGET_NANOS)

const ux_menu_entry_t menu_main[];

const ux_menu_entry_t menu_about[] = {
    {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
    {NULL, NULL, 0, NULL, "Author", "FDS", 0, 0},
    {NULL, NULL, 0, NULL, "Co-Author", "009", 0, 0},
    {menu_main, NULL, 1, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_main[] = {
    {NULL, NULL, 0, &C_icon_NEM, "Welcome to", "  NEM wallet", 33, 12},
    {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
    {NULL, os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
    UX_MENU_END};

#endif // #if TARGET_NANOS

#if defined(TARGET_NANOS)
const bagl_element_t ui_address_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_ICON                           , 0x01,  31,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_EYE_BADGE  }, NULL, 0, 0, 0,
    //NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Export",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "NEM account",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Address",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     (char *)fullAddress,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_address_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:                
                //back home
                //UX_CALLBACK_SET_INTERVAL(MAX(
                //    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));     
                if(maxInterval == 0){
                    G_io_apdu_buffer[0] = 0x69; //0x9000 timeout
                    G_io_apdu_buffer[1] = 0x85;
                    // Send back the response, do not restart the event loop
                    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
                    ui_idle();

                }else{
                    maxInterval--;
                    UX_CALLBACK_SET_INTERVAL(MAX(
                        3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));                    
                }
                break;
            }
        }
        return display;
    }
    return 1;
}

unsigned int ui_address_nanos_button(unsigned int button_mask,
                                     unsigned int button_mask_counter);
#endif // #if defined(TARGET_NANOS)

#if defined(TARGET_NANOS)
const char * const ui_approval_details[][2] = {
    {detailName[0], mainInfo[0]},
    {detailName[1], mainInfo[1]},
    {detailName[2], mainInfo[2]},
    {detailName[3], mainInfo[3]},
    {detailName[4], extraInfo[0]},
    {detailName[5], extraInfo[1]},
    {detailName[6], extraInfo[2]},
    {detailName[7], extraInfo[3]},
    {detailName[8], extraInfo[4]},
    {detailName[9], extraInfo[5]},
    {detailName[10], extraInfo[6]},
    {detailName[11], extraInfo[7]},
};

const bagl_element_t ui_approval_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_ICON                           , 0x01,  21,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_TRANSACTION_BADGE  }, NULL, 0, 0,
    //0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     (char *)txTypeName, //"transaction",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     NULL, //"Amount",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x12, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     NULL, //(char *)fullAmount,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

};

/*
 ux_step 0: confirm
*//*
unsigned int ui_approval_prepro(const bagl_element_t *element) {
    unsigned int display = 1;
    return display;
}*/

/*
 ux_step 0: confirm
         1: amount 
         2: address
         3: message
         4: [txType]
         5: fees
*/
unsigned int ui_approval_prepro(const bagl_element_t *element) {
    unsigned int display = 1;
    if (element->component.userid > 0) {
        // display the meta element when at least bigger
        display = (ux_step == element->component.userid - 1) || (element->component.userid >= 0x02 && ux_step >= 1);
    PRINTF("check ux_step trong ui_approval_prepro: %d\n", ux_step);
        if (display) {
            switch (element->component.userid) {
            case 0x01:                           
                UX_CALLBACK_SET_INTERVAL(2000);                
                break;
            case 0x02:
            case 0x12:
                os_memmove(&tmp_element, element, sizeof(bagl_element_t));                
                // if ((txContent.txType != TRANSFER) && (txContent.txType != NEMV1_TRANSFER) ) {
                //     // Just show the fees if it is not normal transaction.
                //     ux_step = 5;  
                // }
                display = ux_step - 1;
                switch(display) {
                    case 0: // recipient address 
                    display_detail:
                        tmp_element.text = ui_approval_details[display][(element->component.userid)>>4];
                        break;
                    case 1: // message
                    case 2: // fees
                    case 3: // amount
                    case 4: // mosaic 1
                    case 5: // mosaic 2
                    case 6: // mosaic 3                     
                    case 7: // mosaic 4                     
                    case 8: // mosaic 5                     
                    case 9: // mosaic 6                     
                    case 10: // mosaic 7                     
                    case 11: // mosaic 8                     
                    case 12: // mosaic 9
                        if (display == ux_step_count - 1) {
                            maxInterval--;//back home 
                        }                     
                        goto display_detail;
                }                                    
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(&tmp_element, 7)));
                return &tmp_element;
            }
        }      
    }
    if(maxInterval < 0) { //back home     
        G_io_apdu_buffer[0] = 0x69; //0x9000 timeout
        G_io_apdu_buffer[1] = 0x85;
        // Send back the response, do not restart the event loop
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
        ui_idle();        
    }
    return display;
}

unsigned int ui_approval_nanos_button(unsigned int button_mask,
                                      unsigned int button_mask_counter);

#endif // #if defined(TARGET_NANOS)

void ui_idle(void) {
#if defined(TARGET_NANOS)
    UX_MENU_DISPLAY(0, menu_main, NULL);
#endif // #if TARGET_ID
}

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e) {
    // Go back to the dashboard
    os_sched_exit(0);
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e) {
    uint32_t tx = set_result_get_publicKey();
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    PRINTF("Size %d\n", IO_APDU_BUFFER_SIZE);
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

#if defined(TARGET_NANOS)
unsigned int ui_address_nanos_button(unsigned int button_mask,
                                     unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        io_seproxyhal_touch_address_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // OK
        io_seproxyhal_touch_address_ok(NULL);
        break;
    }
    }
    return 0;
}
#endif // #if defined(TARGET_NANOS)

unsigned int io_seproxyhal_touch_tx_ok(const bagl_element_t *e) {

    uint8_t privateKeyData[32];
    cx_ecfp_private_key_t privateKey;
    cx_ecfp_public_key_t publicKey;
    uint32_t tx = 0;

    os_perso_derive_node_bip32(CX_CURVE_256K1, tmpCtx.transactionContext.bip32Path, tmpCtx.transactionContext.pathLength, privateKeyData, NULL);    
    cx_ecfp_init_public_key(CX_CURVE_Ed25519, NULL, 0, &publicKey);

    if (tmpCtx.transactionContext.algo == CX_KECCAK) {
        uint8_t privateKeyDataR[32];
        uint8_t j;
        for (j=0; j<32; j++) {
            privateKeyDataR[j] = privateKeyData[31 - j];
        }

        cx_ecfp_init_private_key(CX_CURVE_Ed25519, privateKeyDataR, 32, &privateKey);
        os_memset(privateKeyDataR, 0, sizeof(privateKeyDataR));
    }else if (tmpCtx.transactionContext.algo == CX_SHA3) {
        cx_ecfp_init_private_key(CX_CURVE_Ed25519, privateKeyData, 32, &privateKey);
    }else{
        THROW(0x6b00);
    }
    
    //signature 128
    G_io_apdu_buffer[tx++] = 128;
    tx = cx_eddsa_sign(&privateKey, 
                       CX_LAST, 
                       tmpCtx.transactionContext.algo, 
                       raw_tx + 21,
                       tmpCtx.transactionContext.rawTxLength, 
                       NULL, 
                       0, 
                       G_io_apdu_buffer, 
                       NULL);
    cx_ecfp_generate_pair2(CX_CURVE_Ed25519, &publicKey, &privateKey, 1, tmpCtx.transactionContext.algo);


    //public 64
    os_memset(&privateKey, 0, sizeof(privateKey));
    os_memset(privateKeyData, 0, sizeof(privateKeyData));
    
    uint8_t nemPublicKey[32];
    unsigned char outNemAddress[40];
    to_nem_public_key_and_address(&publicKey, tmpCtx.transactionContext.networkId, tmpCtx.transactionContext.algo, &nemPublicKey, &outNemAddress);

    G_io_apdu_buffer[tx++] = 32;
    os_memmove(G_io_apdu_buffer + tx, nemPublicKey, 32);
    tx += 32;

    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_tx_cancel(const bagl_element_t *e) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

#if defined(TARGET_NANOS)

unsigned int ui_approval_nanos_button(unsigned int button_mask,
                                      unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_tx_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: {
        io_seproxyhal_touch_tx_ok(NULL);
        break;
    }
    }
    return 0;
}

#endif // #if defined(TARGET_NANOS)

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

uint32_t set_result_get_publicKey() {
    uint32_t tx = 0;
    uint32_t addressLength = sizeof(tmpCtx.publicKeyContext.address);

    //address
    G_io_apdu_buffer[tx++] = addressLength;
    os_memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.address, addressLength);
    tx += addressLength;

    //publicKey
    G_io_apdu_buffer[tx++] = 32;
    os_memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.nemPublicKey, 32);
    tx += 32;

    return tx;
}

void handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer,
                        uint16_t dataLength, volatile unsigned int *flags,
                        volatile unsigned int *tx) {
    UNUSED(dataLength);
    uint8_t privateKeyData[32];
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint32_t i;
    uint8_t bip32PathLength = *(dataBuffer++);
    cx_ecfp_private_key_t privateKey;
    uint8_t p2Chain = p2 & 0x3F;
    cx_curve_t curve;

    //set default need confirm
    p1 = P1_CONFIRM;

    //bip32PathLength shold be 5
    if (bip32PathLength != MAX_BIP32_PATH) {
        PRINTF("BIP32_PATH_INVALID\n");
        THROW(0x6a80);
    }

    if ((p1 != P1_CONFIRM) && (p1 != P1_NON_CONFIRM)) {
        THROW(0x6B00);
    }
    if ((p2Chain != P2_CHAINCODE) && (p2Chain != P2_NO_CHAINCODE)) {
        THROW(0x6B00);
    }
   
    for (i = 0; i < bip32PathLength; i++) {
        bip32Path[i] = (dataBuffer[0] << 24) | (dataBuffer[1] << 16) |
                       (dataBuffer[2] << 8) | (dataBuffer[3]);
        dataBuffer += 4;
    }

    tmpCtx.publicKeyContext.networkId = readNetworkIdFromBip32path(bip32Path);
    if (tmpCtx.publicKeyContext.networkId == NEM_MAINNET || tmpCtx.publicKeyContext.networkId == NEM_TESTNET) {
        tmpCtx.publicKeyContext.algo = CX_KECCAK;
    } else {
        tmpCtx.publicKeyContext.algo = CX_SHA3;
    }
    
    //tmpCtx.publicKeyContext.getChaincode = (p2Chain == P2_CHAINCODE);   
    os_perso_derive_node_bip32(CX_CURVE_256K1, bip32Path, bip32PathLength, privateKeyData, NULL);

    if (tmpCtx.publicKeyContext.algo == CX_SHA3) {
        cx_ecfp_init_private_key(CX_CURVE_Ed25519, privateKeyData, 32, &privateKey);
    }else if (tmpCtx.publicKeyContext.algo == CX_KECCAK) { //CX_KECCAK
        //reverse privateKey
        uint8_t privateKeyDataR[32];
        uint8_t j;
        for (j=0; j<32; j++) {
            privateKeyDataR[j] = privateKeyData[31 - j];
        }
        cx_ecfp_init_private_key(CX_CURVE_Ed25519, privateKeyDataR, 32, &privateKey);
        os_memset(privateKeyDataR, 0, sizeof(privateKeyDataR));
    }else{ 
        THROW(0x6a80);
    }
    cx_ecfp_generate_pair2(CX_CURVE_Ed25519, &tmpCtx.publicKeyContext.publicKey, &privateKey, 1, tmpCtx.publicKeyContext.algo);

    os_memset(privateKeyData, 0, sizeof(privateKeyData));
    os_memset(&privateKey, 0, sizeof(privateKey));   

    to_nem_public_key_and_address(
                                  &tmpCtx.publicKeyContext.publicKey, 
                                  tmpCtx.publicKeyContext.networkId, 
                                  tmpCtx.publicKeyContext.algo, 
                                  &tmpCtx.publicKeyContext.nemPublicKey, 
                                  &tmpCtx.publicKeyContext.address
                                  );

    uint8_t addressLength = sizeof(tmpCtx.publicKeyContext.address);

    os_memset(fullAddress, 0, sizeof(fullAddress));
    os_memmove((void *)fullAddress, tmpCtx.publicKeyContext.address, 6);
    os_memmove((void *)(fullAddress + 6), "~", 1);
    os_memmove((void *)(fullAddress + 7), tmpCtx.publicKeyContext.address + addressLength - 4, 4);

    // prepare for a UI based reply//
#if defined(TARGET_NANOS)
#if 0        
    snprintf(fullAddress, sizeof(fullAddress), " 0x%.*s ", 40,
             tmpCtx.publicKeyContext.address);
#endif                 
    ux_step = 0;
    ux_step_count = 2;
    maxInterval = MAX_UX_CALLBACK_INTERVAL + 1 + 1;
    UX_DISPLAY(ui_address_nanos, ui_address_prepro);
#endif // #if TARGET

    *flags |= IO_ASYNCH_REPLY;
    //end: Go show address on ledger
}


void display_tx(uint8_t *raw_tx, uint16_t dataLength, 
                volatile unsigned int *flags, volatile unsigned int *tx ) {
    UNUSED(tx);
    uint8_t addressLength;
    uint32_t i;

    tmpCtx.transactionContext.pathLength = raw_tx[0];
    if (tmpCtx.transactionContext.pathLength != MAX_BIP32_PATH) {
        PRINTF("BIP32_PATH_Invalid\n");
        THROW(0x6a80);
    }

    for (i = 0; i < tmpCtx.transactionContext.pathLength; i++) {
        tmpCtx.transactionContext.bip32Path[i] =
            (raw_tx[1 + i*4] << 24) | (raw_tx[2 + i*4] << 16) |
            (raw_tx[3 + i*4] << 8) | (raw_tx[4 + i*4]);
    }

    tmpCtx.transactionContext.networkId = readNetworkIdFromBip32path(tmpCtx.transactionContext.bip32Path);
    if (tmpCtx.transactionContext.networkId == NEM_MAINNET || tmpCtx.transactionContext.networkId == NEM_TESTNET) {
        tmpCtx.transactionContext.algo = CX_KECCAK;
    } else {
        tmpCtx.transactionContext.algo = CX_SHA3;
    }
    
    // Load dataLength of tx
    tmpCtx.transactionContext.rawTxLength = dataLength - 21; 
    
    //NEM_MAINNET || NEM_TESTNET
    //txType
    uint32_t txType = getUint32(reverseBytes(&raw_tx[21], 4));
    txContent.txType = (uint16_t *)txType;
    PRINTF("Type: %x\n", txContent.txType);

    uint32_t txVersion = getUint32(reverseBytes(&raw_tx[21+4], 4));

    //fee
    uint64_t fee = getUint32(reverseBytes(&raw_tx[21+4+4+4+4+32], 4));
    print_amount((uint64_t *)fee, 6, "xem", &mainInfo[2]);
    SPRINTF(detailName[2], "%s", "Network Fee");

    //Recipient Address
    char tmpAddress[41];

    //msg
    uint16_t lengthOfMessFeildIndex;
    uint32_t lengthOfMessFeild;
    uint16_t msgSizeIndex;
    uint32_t msgSize;
    uint16_t msgTypeIndex;
    uint16_t msgIndex;
    uint32_t msgType;
    char msg[MAX_PRINT_MESSAGE_LENGTH + 1];

    //mosaics
    uint16_t numberOfMosaicsIndex;
    uint8_t numberOfMosaics; 
    uint16_t mosaicIndex;

    //amount
    uint16_t amountIndex;
    uint32_t amount; 

    //Namespace ID
    uint16_t lengthOfIDIndex;
    uint32_t lengthOfID;
    uint16_t IDNameIndex;

    //Mosaic Name
    uint16_t lengthOfNameIndex;
    uint32_t lengthOfName;
    uint16_t nameIndex;
    char IDName[MAX_PRINT_EXTRA_INFOR_LENGTH];
    char name[MAX_PRINT_EXTRA_INFOR_LENGTH];

    //Supply type
    uint8_t supplyType; 

    //Quantity
    uint16_t quantityIndex;
    uint32_t quantity;

    //Array index
    uint8_t arrayIndex; 

    switch(txContent.txType){
        case NEMV1_TRANSFER: //Transfer  
            ux_step_count = 5;
            SPRINTF(txTypeName, "%s", "transfer tx");

            //Address
            SPRINTF(detailName[0], "%s", "Recipient");
            uint2Ascii(&raw_tx[21+4+4+4+4+32+4+4+4+4], 40, tmpAddress);
    PRINTF("Address: %s\n", tmpAddress);
            os_memset(mainInfo[0], 0, sizeof(mainInfo[0]));                
            os_memmove((void *)mainInfo[0], tmpAddress, 6);
            os_memmove((void *)(mainInfo[0] + 6), "~", 1);
            os_memmove((void *)(mainInfo[0] + 6 + 1), tmpAddress + 40 - 4, 4);

            //Message
            SPRINTF(detailName[1], "%s", "Message");
            lengthOfMessFeildIndex = 21+4+4+4+4+32+4+4+4+4+40+4+4;
            lengthOfMessFeild = getUint32(reverseBytes(&raw_tx[lengthOfMessFeildIndex], 4));
    PRINTF("lengthOfMessFeild: %d\n", lengthOfMessFeild);
            msgSizeIndex = lengthOfMessFeild == 0 ? 0 : lengthOfMessFeildIndex+4+4;
            msgSize = lengthOfMessFeild == 0 ? 0 : getUint32(reverseBytes(&raw_tx[msgSizeIndex], 4));

            //mosaics
            numberOfMosaicsIndex = lengthOfMessFeild == 0 ? lengthOfMessFeildIndex+4: lengthOfMessFeildIndex+4+4+4+msgSize;
            numberOfMosaics = getUint32(reverseBytes(&raw_tx[numberOfMosaicsIndex], 4));
            mosaicIndex = numberOfMosaicsIndex+4;
    PRINTF("numberOfMosaics: %d\n", numberOfMosaics);
            
            //amount
    PRINTF("amount: %d\n", getUint32(reverseBytes(&raw_tx[21+4+4+4+4+32+4+4+4+4+40], 4)));
            SPRINTF(detailName[3], "%s", "Amount");
            if (numberOfMosaics == 0) {
                amountIndex = 21+4+4+4+4+32+4+4+4+4+40;
                amount = getUint32(reverseBytes(&raw_tx[amountIndex], 4));
                print_amount((uint64_t *)amount, 6, "xem", &mainInfo[3]);
            } else {
                SPRINTF(mainInfo[3], "<find %d mosaics>", numberOfMosaics);
                
                //Show all mosaics on Ledger
                for (arrayIndex = 0; arrayIndex < numberOfMosaics; arrayIndex++) {
                    SPRINTF(detailName[4 + arrayIndex], "%s %d", "Mosaic", 1 + arrayIndex);
                    //Namespace ID
                    lengthOfIDIndex = mosaicIndex+4+4;
                    lengthOfID = getUint32(reverseBytes(&raw_tx[lengthOfIDIndex], 4));
                    IDNameIndex = mosaicIndex+4+4+4;
                    mosaicIndex = IDNameIndex + lengthOfID;
                    uint2Ascii(&raw_tx[IDNameIndex], lengthOfID, IDName);
            PRINTF("lengthOfID: %d\n", lengthOfID);
            PRINTF("mosaic name: %s\n", IDName);

                    //Mosaic Name
                    lengthOfNameIndex = mosaicIndex;
                    lengthOfName = getUint32(reverseBytes(&raw_tx[lengthOfNameIndex], 4));
            PRINTF("length of name: %d \n",lengthOfName);
                    nameIndex = lengthOfNameIndex+4;
                    mosaicIndex = nameIndex + lengthOfName;
                    uint2Ascii(&raw_tx[nameIndex], lengthOfName, name);
            PRINTF("mosaic name: %s\n", name);

                    //Quantity
                    quantity = getUint32(reverseBytes(&raw_tx[mosaicIndex], 4));
                    // print_amount((uint64_t *)quantity, 6, "xem", &mainInfo[3]);
                    ux_step_count++;
                    if ((compare_strings(IDName,"nem") == 0) && (compare_strings(name,"xem") == 0)) {
                        print_amount((uint64_t *)quantity, 6, "xem", extraInfo[arrayIndex]);
                    } else {
                        if (string_length(name) < 13) {
                            SPRINTF(extraInfo[arrayIndex], "%d %s", quantity, name);
                        } else {
                            SPRINTF(extraInfo[arrayIndex], "%d %s...", quantity, name);
                        }
                    }
                    mosaicIndex += 8;
            PRINTF("OK Mosaic Quantity 1: %d \n\n", quantity);
                    // print_amount((uint64_t *)quantity, 6, name, IDName);
                    // volatile SPRINTF(mainInfo[1], "%s\0", toCh);
                    // SPRINTF(mosaicShow, "%s.%s: %d\0", IDName, name, quantity);
                }
            }

            //msg
            msgTypeIndex = lengthOfMessFeildIndex+4;
            msgIndex = lengthOfMessFeildIndex+4+4+4;
            msgType = getUint32(reverseBytes(&raw_tx[msgTypeIndex], 4));
            if (lengthOfMessFeild == 0) {
                SPRINTF(mainInfo[1], "%s\0", "<empty msg>");
            }
            else if(msgType == 1) {
                if(msgSize > MAX_PRINT_MESSAGE_LENGTH){
                    uint2Ascii(&raw_tx[msgIndex], MAX_PRINT_MESSAGE_LENGTH, msg);
                    SPRINTF(mainInfo[1], "  %s ...\0", msg);
                }else{
                    uint2Ascii(&raw_tx[msgIndex], msgSize, msg);
                    SPRINTF(mainInfo[1], "%s\0", msg);
                }
            } else {
                SPRINTF(mainInfo[1], "%s\0", "<encrypted msg>");
            }     

            break; 
        case NEMV1_MULTISIG_SIGNATURE:
            // ux_step_count = 5;
            ux_step_count = 2;
            SPRINTF(txTypeName, "%s", "Mulisig signature");

    PRINTF("address: %s\n", tmpAddress);
            break;
        case NEMV1_MULTISIG_TRANSACTION:
            ux_step_count = 5;
            SPRINTF(txTypeName, "%s", "Mulisig TX");

            //Address
            uint2Ascii(&raw_tx[21+4+4+4+4+32+4+4+4+4], 40, tmpAddress);
            os_memset(mainInfo[0], 0, sizeof(mainInfo[0]));                
            os_memmove((void *)mainInfo[0], tmpAddress, 6);
            os_memmove((void *)(mainInfo[0] + 6), "~", 1);
            os_memmove((void *)(mainInfo[0] + 6 + 1), tmpAddress + 40 - 4, 4);
            break;
        case NEMV1_PROVISION_NAMESPACE:
            ux_step_count = 6;
            SPRINTF(txTypeName, "%s", "Namespace TX");

            //Sink Address
            SPRINTF(detailName[0], "%s", "Sink Address");
            uint2Ascii(&raw_tx[21+4+4+4+4+32+4+4+4+4], 40, tmpAddress);
        PRINTF("Address: %s\n", tmpAddress);
            os_memset(mainInfo[0], 0, sizeof(mainInfo[0]));                
            os_memmove((void *)mainInfo[0], tmpAddress, 6);
            os_memmove((void *)(mainInfo[0] + 6), "~", 1);
            os_memmove((void *)(mainInfo[0] + 6 + 1), tmpAddress + 40 - 4, 4);

            //Rental Fee
            SPRINTF(detailName[1], "%s", "Rental Fee");
            quantityIndex = 21+4+4+4+4+32+4+4+4+4+40;
            quantity = getUint32(reverseBytes(&raw_tx[quantityIndex], 4));
            print_amount((uint64_t *)quantity, 6, "xem", mainInfo[1]);

            //Fee
            //SPRINTF(detailName[2], "%s", "Network Fee");

            //Namespace
            SPRINTF(detailName[3], "%s", "Namespace");
            msgSizeIndex = quantityIndex + 8;
            msgSize = getUint32(reverseBytes(&raw_tx[msgSizeIndex], 4));
            msgIndex = msgSizeIndex + 4;
            uint2Ascii(&raw_tx[msgIndex], msgSize, msg);
        PRINTF("Namespace: %s\n", msg);
            SPRINTF(mainInfo[3], "%s", msg);

            //Parent namespace
            SPRINTF(detailName[4], "%s", "Parent Name");
            msgSizeIndex = msgIndex + msgSize;
            msgSize = getUint32(reverseBytes(&raw_tx[msgSizeIndex], 4));
            if (msgSize == -1) {
                SPRINTF(extraInfo[0], "%s", "<New namespace>"); 
            } else {
                msgIndex = msgSizeIndex + 4;
                uint2Ascii(&raw_tx[msgIndex], msgSize, msg);
                SPRINTF(extraInfo[0], "%s", msg);
            }
            break;                
        case NEMV1_MOSAIC_DEFINITION:
            ux_step_count = 11;
            SPRINTF(txTypeName, "%s", "Create Mosaic");

            //Namespace ID
            SPRINTF(detailName[0], "%s", "Namespace");
            lengthOfIDIndex = 21+16+32+16+32+4+4;
            lengthOfID = getUint32(reverseBytes(&raw_tx[lengthOfIDIndex], 4));
            IDNameIndex= lengthOfIDIndex+4;
            uint2Ascii(&raw_tx[IDNameIndex], lengthOfID, IDName);
            SPRINTF(mainInfo[0], "%s", IDName);

            //Mosaic Name
            SPRINTF(detailName[1], "%s", "Mosaic Name");
            lengthOfNameIndex = IDNameIndex + lengthOfID;
            lengthOfName = getUint32(reverseBytes(&raw_tx[lengthOfNameIndex], 4));
            nameIndex = lengthOfNameIndex+4;
            uint2Ascii(&raw_tx[nameIndex], lengthOfName, name);
            SPRINTF(mainInfo[1], "%s", name);

            //Description
            SPRINTF(detailName[4], "%s", "Description");
            msgSizeIndex = nameIndex+lengthOfName;
            msgSize = getUint32(reverseBytes(&raw_tx[msgSizeIndex], 4));
            msgIndex = msgSizeIndex+4;
            if(msgSize > MAX_PRINT_MESSAGE_LENGTH){
                uint2Ascii(&raw_tx[msgIndex], MAX_PRINT_MESSAGE_LENGTH, msg);
                SPRINTF(extraInfo[0], "%s...\0", msg);
            } else {
                uint2Ascii(&raw_tx[msgIndex], msgSize, msg);
                SPRINTF(extraInfo[0], "%s\0", msg);
            }

            //Start Properties
            //divisibility
            SPRINTF(detailName[6], "%s", "Divisibility");
            msgIndex = msgIndex + msgSize + 4+4+4+12+4;
            uint2Ascii(&raw_tx[msgIndex], 1, msg);
            SPRINTF(extraInfo[2], "%s", msg);

            //initial Supply
            SPRINTF(detailName[5], "%s", "Initial Supply");
            msgSizeIndex = msgIndex+1 + 4+4+13;
            msgSize = getUint32(reverseBytes(&raw_tx[msgSizeIndex], 4));
            msgIndex = msgSizeIndex + 4;
            uint2Ascii(&raw_tx[msgIndex], msgSize, msg);
            SPRINTF(extraInfo[1], "%s", msg);

            //Transferable
            SPRINTF(detailName[7], "%s", "Mutable Supply");
            msgSizeIndex = msgIndex+msgSize + 4+4+13;
            msgSize = getUint32(reverseBytes(&raw_tx[msgSizeIndex], 4));
            msgIndex = msgSizeIndex + 4;
            uint2Ascii(&raw_tx[msgIndex], msgSize, msg);
            SPRINTF(extraInfo[3], "%s", compare_strings(msg, "true") == 0 ? "Yes" : "No");

            //Mutable Supply
            SPRINTF(detailName[8], "%s", "Transferable");
            msgSizeIndex = msgIndex+msgSize + 4+4+12;
            msgSize = getUint32(reverseBytes(&raw_tx[msgSizeIndex], 4));
            msgIndex = msgSizeIndex + 4;
            uint2Ascii(&raw_tx[msgIndex], msgSize, msg);
            SPRINTF(extraInfo[4], "%s", compare_strings(msg, "true") == 0 ? "Yes" : "No");

            //Requires Levy
            SPRINTF(detailName[9], "%s", "Requires Levy");
            msgSizeIndex = msgIndex+msgSize;
            msgSize = getUint32(reverseBytes(&raw_tx[msgSizeIndex], 4));
            SPRINTF(extraInfo[5], "%s", msgSize == 0 ? "No" : "Yes");

            //Rental Fee
            SPRINTF(detailName[3], "%s", "Rental Fee");
            quantityIndex = msgSizeIndex+msgSize + 4+4+40;
            quantity = getUint32(reverseBytes(&raw_tx[quantityIndex], 4));
            print_amount((uint64_t *)quantity, 6, "xem",mainInfo[3]);

            //End Properties
                
            break; 
        case NEMV1_MOSAIC_SUPPLY_CHANGE:
            ux_step_count = 5;
            SPRINTF(txTypeName, "%s", "Mosaic Supply");

            //Namespace ID
            SPRINTF(detailName[0], "%s", "Namespace");
            lengthOfIDIndex = 21+16+32+12+4;
            lengthOfID = getUint32(reverseBytes(&raw_tx[lengthOfIDIndex], 4));
            IDNameIndex= lengthOfIDIndex+4;
            uint2Ascii(&raw_tx[IDNameIndex], lengthOfID, IDName);
            SPRINTF(mainInfo[0], "%s", IDName);
        PRINTF("length of ID name: %d \n",lengthOfID);
        PRINTF("ID name: %s\n", IDName);

            //Mosaic Name
            SPRINTF(detailName[1], "%s", "Mosaic Name");
            lengthOfNameIndex = IDNameIndex + lengthOfID;
            lengthOfName = getUint32(reverseBytes(&raw_tx[lengthOfNameIndex], 4));
        PRINTF("length of name: %d \n",lengthOfName);
            nameIndex = lengthOfNameIndex+4;
            uint2Ascii(&raw_tx[nameIndex], lengthOfName, name);
            SPRINTF(mainInfo[1], "%s", name);
        PRINTF("name: %s \n",name);

            //Supply type
            supplyType = getUint32(reverseBytes(&raw_tx[nameIndex+lengthOfName], 4));
            quantity = getUint32(reverseBytes(&raw_tx[nameIndex+lengthOfName+4], 4));
            if (supplyType == 0x01) {   //Increase supply
                SPRINTF(detailName[3], "%s", "Increase");
            } else { //Decrease supply 
                SPRINTF(detailName[3], "%s", "Decrease");
            }
            SPRINTF(mainInfo[3], "%d", quantity);

            break;         
        default:
            SPRINTF(txTypeName, "tx type %d", txContent.txType);     
    }   

#if defined(TARGET_NANOS)
    ux_step = 0;
    // "confirm", amount, address, msgPayload, [txtype], fees
    //ux_step_count = 5;
    /*
    if (txContent.txtype) {
        ux_step_count++;
    }*/
    maxInterval = MAX_UX_CALLBACK_INTERVAL + 1;
    UX_DISPLAY(ui_approval_nanos, ui_approval_prepro);
#endif // #if TARGET

    *flags |= IO_ASYNCH_REPLY;
}

void handleSign(volatile unsigned int *flags, volatile unsigned int *tx) {
    // check the third byte (0x02) for the instruction subtype.
    if ((G_io_apdu_buffer[OFFSET_P1] == P1_FIRST) || (G_io_apdu_buffer[OFFSET_P1] == P1_LAST)) {
        clean_raw_tx(raw_tx);
        hashTainted = 1;
    }

    // if this is the first transaction part, reset the hash and all the other temporary variables.
    if (hashTainted) {
        hashTainted = 0;
        raw_tx_ix = 0;
        raw_tx_len = 0;
    }

    // move the contents of the buffer into raw_tx, and update raw_tx_ix to the end of the buffer, 
    // to be ready for the next part of the tx.
    unsigned int len = get_apdu_buffer_length();
    unsigned char * in = G_io_apdu_buffer + OFFSET_CDATA;
    unsigned char * out = raw_tx + raw_tx_ix;
    if (raw_tx_ix + len > MAX_TX_RAW_LENGTH) {
        hashTainted = 1;
        THROW(0x6D08);
    }
    os_memmove(out, in, len);
    raw_tx_ix += len;

    // set the buffer to end with a zero.
    G_io_apdu_buffer[OFFSET_CDATA + len] = '\0';

    // if this is the last part of the transaction, parse the transaction into human readable text, and display it.
    if ((G_io_apdu_buffer[OFFSET_P1] == P1_MORE) || (G_io_apdu_buffer[OFFSET_P1] == P1_LAST))  {
        raw_tx_len = raw_tx_ix;
        raw_tx_ix = 0;

        // parse the transaction into human readable text.
        display_tx(&raw_tx, raw_tx_len, flags, tx);
    } else {
        // continue reading the tx
        THROW(0x9000);  
    }
}

void handleGetAppConfiguration(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                               uint16_t dataLength,
                               volatile unsigned int *flags,
                               volatile unsigned int *tx) {
    UNUSED(p1);
    UNUSED(p2);
    UNUSED(workBuffer);
    UNUSED(dataLength);
    UNUSED(flags);
    G_io_apdu_buffer[0] = 0x00;
    G_io_apdu_buffer[1] = LEDGER_MAJOR_VERSION;
    G_io_apdu_buffer[2] = LEDGER_MINOR_VERSION;
    G_io_apdu_buffer[3] = LEDGER_PATCH_VERSION;
    *tx = 4;
    THROW(0x9000);
}

void nem_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    hashTainted = 1;
                    THROW(0x6982);
                }

                //PRINTF("New APDU received:\n%.*H\n", rx, G_io_apdu_buffer);

                // if the buffer doesn't start with the magic byte, return an error.
                if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                    hashTainted = 1;
                    THROW(0x6E00);
                }

                // check the second byte (0x01) for the instruction.
				switch (G_io_apdu_buffer[OFFSET_INS]) {
                
                case INS_GET_PUBLIC_KEY: 
                handleGetPublicKey(G_io_apdu_buffer[OFFSET_P1],
                                G_io_apdu_buffer[OFFSET_P2],
                                G_io_apdu_buffer + OFFSET_CDATA,
                                G_io_apdu_buffer[OFFSET_LC], &flags, &tx);
                break;

                //Sign a transaction
                case INS_SIGN: 
                handleSign(&flags, &tx);
                break;

                case INS_GET_APP_CONFIGURATION:
                handleGetAppConfiguration(
                    G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2],
                    G_io_apdu_buffer + OFFSET_CDATA,
                    G_io_apdu_buffer[OFFSET_LC], &flags, &tx);
                break;

                default:
                    THROW(0x6D00);
                    break;
                }
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                case 0x6000:
                    // Wipe the transaction context and report the exception
                    sw = e;
                    os_memset(&txContent, 0, sizeof(txContent));
                    break;
                case 0x9000:
                    // All is well
                    sw = e;
                    break;
                default:
                    // Internal error
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }

    // return_to_dashboard:
    return;
}

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_STATUS_EVENT:
        if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
            !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
              SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
            THROW(EXCEPTION_IO_RESET);
        }
    // no break is intentional
    default:
        UX_DEFAULT_EVENT();
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT({});
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
            if (UX_ALLOWED) {
#if 0
                if (skipWarning && (ux_step == 0)) {
                    ux_step++;
                }
#endif

                if (ux_step_count) {
                    // prepare next screen
                    ux_step = (ux_step + 1) % ux_step_count;
                    // redisplay screen
                    UX_REDISPLAY();
                }
            }
        });
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    raw_tx_ix = 0;
	hashTainted = 1;

    // ensure exception will work as planned
    os_boot();

    for (;;) {
	    os_memset(&txContent, 0, sizeof(txContent));
	
        UX_INIT();
        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

                USB_power(1);

                ui_idle();
                nem_main();
            }
                CATCH(EXCEPTION_IO_RESET) {
                    // reset IO and UX
                    continue;
                }
                CATCH_ALL {
                    break;
                }
            FINALLY {
            }
        }
        END_TRY;
    }
    app_exit();

    return 0;
}
