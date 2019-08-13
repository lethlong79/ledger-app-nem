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
volatile char detailName[MAX_PRINT_SCREEN][MAX_PRINT_DETAIL_NAME_LENGTH];
//Registers save information to show on the bottom line of screen
volatile char extraInfo[MAX_PRINT_SCREEN][MAX_PRINT_EXTRA_INFOR_LENGTH];

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
    {detailName[0], extraInfo[0]},
    {detailName[1], extraInfo[1]},
    {detailName[2], extraInfo[2]},
    {detailName[3], extraInfo[3]},
    {detailName[4], extraInfo[4]},
    {detailName[5], extraInfo[5]},
    {detailName[6], extraInfo[6]},
    {detailName[7], extraInfo[7]},
    {detailName[8], extraInfo[8]},
    {detailName[9], extraInfo[9]},
    {detailName[10], extraInfo[10]},
    // {detailName[11], extraInfo[11]},
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
        if (display) {
            switch (element->component.userid) {
            case 0x01:                           
                UX_CALLBACK_SET_INTERVAL(2000);                
                break;
            case 0x02:
            case 0x12:
                os_memmove(&tmp_element, element, sizeof(bagl_element_t));                
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
                        if (display == (ux_step_count - 1)) {
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

    uint32_t txVersion = getUint32(reverseBytes(&raw_tx[21+4], 4));

    //Distance index: use for calculating the inner index of multisig tx
    uint8_t disIndex; 

    switch(txContent.txType){
        case NEMV1_TRANSFER: //Transfer 
            disIndex = 21; 
            SPRINTF(txTypeName, "%s", "transfer tx");
            parse_transfer_tx (raw_tx + disIndex,
                &ux_step_count, 
                detailName,
                extraInfo,
                false
            ); 
            break;
        case NEMV1_MULTISIG_MODIFICATION:
            disIndex = 21;
            SPRINTF(txTypeName, "%s", "Convert2Multisig");
            parse_aggregate_modification_tx (raw_tx + disIndex,
                &ux_step_count, 
                detailName,
                extraInfo,
                false,
                tmpCtx.transactionContext.networkId
            ); 
            break;
        case NEMV1_MULTISIG_SIGNATURE:
            SPRINTF(txTypeName, "%s", "Mulisig signature");
            disIndex = 21;
            parse_multisig_signature_tx (raw_tx + disIndex,
                &ux_step_count, 
                detailName,
                extraInfo
            );
            break;
        case NEMV1_MULTISIG_TRANSACTION:
            SPRINTF(txTypeName, "%s", "Mulisig TX");
            disIndex = 21+4+4+4+4+32+8+4+4;
            parse_multisig_tx (raw_tx + disIndex,
                &ux_step_count, 
                detailName,
                extraInfo,
                tmpCtx.transactionContext.networkId
            );
            break;
        case NEMV1_PROVISION_NAMESPACE:
            disIndex = 21;
            SPRINTF(txTypeName, "%s", "Namespace TX");
            parse_provision_namespace_tx (raw_tx + disIndex,
                &ux_step_count, 
                detailName,
                extraInfo,
                false
            );
            break;                
        case NEMV1_MOSAIC_DEFINITION:
            disIndex = 21;
            SPRINTF(txTypeName, "%s", "Create Mosaic");
            parse_mosaic_definition_tx (raw_tx + disIndex,
                &ux_step_count, 
                detailName,
                extraInfo,
                false
            );
            break; 
        case NEMV1_MOSAIC_SUPPLY_CHANGE:
            disIndex = 21;
            SPRINTF(txTypeName, "%s", "Mosaic Supply");
            parse_mosaic_supply_change_tx (raw_tx + disIndex,
                &ux_step_count, 
                detailName,
                extraInfo,
                false
            );
            break;         
        default:
            SPRINTF(txTypeName, "tx type %d", txContent.txType); 
            break;    
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

                PRINTF("New APDU received:\n%.*H\n", rx, G_io_apdu_buffer);

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
