#ifndef NXP_HELPERS_H
#define NXP_HELPERS_H

#include <Python.h>
#include <stdio.h>

#define TX_RX_BUFFER_SIZE           128 // 128 Byte buffer
#define DATA_BUFFER_LEN             16  /* Buffer length */
#define MFC_BLOCK_DATA_SIZE         4   /* Block Data size - 16 Bytes */
#define PHAL_MFC_VERSION_LENGTH     0x08 // from src/phalMFC_Int.h

/*******************************************************************************
**   Global Variable Declaration
*******************************************************************************/
phbalReg_Stub_DataParams_t sBalReader;  /* BAL component holder */

/*
 * HAL variables
 */
phhalHw_Nfc_Ic_DataParams_t sHal_Nfc_Ic;        /* HAL component holder for Nfc Ic's */
void *pHal;                     /* HAL pointer */
uint8_t bHalBufferTx[TX_RX_BUFFER_SIZE];        /* HAL TX buffer */
uint8_t bHalBufferRx[TX_RX_BUFFER_SIZE];        /* HAL RX buffer */

/*
 * PAL variables
 */
phpalI14443p3a_Sw_DataParams_t spalI14443p3a;   /* PAL I14443-A component */
phpalI14443p4a_Sw_DataParams_t spalI14443p4a;   /* PAL ISO I14443-4A component */
phpalI14443p3b_Sw_DataParams_t spalI14443p3b;   /* PAL ISO I14443-B component */
phpalI14443p4_Sw_DataParams_t spalI14443p4;     /* PAL ISO I14443-4 component */
phpalMifare_Sw_DataParams_t spalMifare; /* PAL MIFARE component */

phacDiscLoop_Sw_DataParams_t sDiscLoop; /* Discovery loop component */
phalMfc_Sw_DataParams_t salMfc; /* MIFARE Classic parameter structure */

uint8_t bDataBuffer[DATA_BUFFER_LEN];   /* universal data buffer */

/** General information bytes to be sent with ATR */
const uint8_t GI[] = { 0x46, 0x66, 0x6D,
    0x01, 0x01, 0x10, /*VERSION*/ 0x03, 0x02, 0x00, 0x01, /*WKS*/ 0x04, 0x01, 0xF1 /*LTO*/
};

static uint8_t aData[50];       /* ATR response holder */


static phStatus_t LoadProfile(void)
{
    phStatus_t status = PH_ERR_SUCCESS;

    sDiscLoop.pPal1443p3aDataParams = &spalI14443p3a;
    sDiscLoop.pPal1443p3bDataParams = &spalI14443p3b;
    sDiscLoop.pPal1443p4aDataParams = &spalI14443p4a;
    sDiscLoop.pPal14443p4DataParams = &spalI14443p4;
    sDiscLoop.pHalDataParams = &sHal_Nfc_Ic.sHal;

    /*
     * These lines are added just to SIGSEG fault when non 14443-3 card is detected
     */
    /*
     * Assign the GI for Type A
     */
    sDiscLoop.sTypeATargetInfo.sTypeA_P2P.pGi = (uint8_t *) GI;
    sDiscLoop.sTypeATargetInfo.sTypeA_P2P.bGiLength = sizeof(GI);
    /*
     * Assign the GI for Type F
     */
    sDiscLoop.sTypeFTargetInfo.sTypeF_P2P.pGi = (uint8_t *) GI;
    sDiscLoop.sTypeFTargetInfo.sTypeF_P2P.bGiLength = sizeof(GI);
    /*
     * Assign ATR response for Type A
     */
    sDiscLoop.sTypeATargetInfo.sTypeA_P2P.pAtrRes = aData;
    /*
     * Assign ATR response for Type F
     */
    sDiscLoop.sTypeFTargetInfo.sTypeF_P2P.pAtrRes = aData;
    /*
     * Assign ATS buffer for Type A
     */
    sDiscLoop.sTypeATargetInfo.sTypeA_I3P4.pAts = aData;
    /*
     ******************************************************************************************** */

    /*
     * Passive Bailout bitmap configuration
     */
    status = phacDiscLoop_SetConfig(&sDiscLoop, PHAC_DISCLOOP_CONFIG_BAIL_OUT, PH_OFF);
    PH_CHECK_SUCCESS(status);

    /*
     * Passive poll bitmap configuration. Poll for only Type A Tags.
     */
    status = phacDiscLoop_SetConfig(&sDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, PHAC_DISCLOOP_POS_BIT_MASK_A);
    PH_CHECK_SUCCESS(status);

    /*
     * Turn OFF Passive Listen.
     */
    status = phacDiscLoop_SetConfig(&sDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_LIS_TECH_CFG, PH_OFF);
    PH_CHECK_SUCCESS(status);

    /*
     * Turn OFF active listen.
     */
    status = phacDiscLoop_SetConfig(&sDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_LIS_TECH_CFG, PH_OFF);
    PH_CHECK_SUCCESS(status);

    /*
     * Turn OFF Active Poll
     */
    status = phacDiscLoop_SetConfig(&sDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_POLL_TECH_CFG, PH_OFF);
    PH_CHECK_SUCCESS(status);

    /*
     * Disable LPCD feature.
     */
    status = phacDiscLoop_SetConfig(&sDiscLoop, PHAC_DISCLOOP_CONFIG_ENABLE_LPCD, PH_OFF);
    PH_CHECK_SUCCESS(status);

    /*
     * reset collision Pending
     */
    status = phacDiscLoop_SetConfig(&sDiscLoop, PHAC_DISCLOOP_CONFIG_COLLISION_PENDING, PH_OFF);
    PH_CHECK_SUCCESS(status);

    /*
     * whether anti-collision is supported or not.
     */
    status = phacDiscLoop_SetConfig(&sDiscLoop, PHAC_DISCLOOP_CONFIG_ANTI_COLL, PH_ON);
    PH_CHECK_SUCCESS(status);

    /*
     * Device limit for Type A
     */
    status = phacDiscLoop_SetConfig(&sDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_DEVICE_LIMIT, PH_ON);
    PH_CHECK_SUCCESS(status);

    /*
     * Discovery loop Operation mode
     */
    status = phacDiscLoop_SetConfig(&sDiscLoop, PHAC_DISCLOOP_CONFIG_OPE_MODE, RD_LIB_MODE_NFC);
    PH_CHECK_SUCCESS(status);

    /*
     * Bailout on Type A detect
     */
    status = phacDiscLoop_SetConfig(&sDiscLoop, PHAC_DISCLOOP_CONFIG_BAIL_OUT, PHAC_DISCLOOP_POS_BIT_MASK_A);
    PH_CHECK_SUCCESS(status);

    /*
     * Return Status
     */
    return status;
}


phStatus_t NfcRdLibInit(void)
{
    phStatus_t status;

    /*
     * Initialize the Reader BAL (Bus Abstraction Layer) component
     */
    status = phbalReg_Stub_Init(&sBalReader, sizeof(phbalReg_Stub_DataParams_t));
    PH_CHECK_SUCCESS(status);

    /*
     * Initialize the OSAL Events.
     */
    status = phOsal_Event_Init();
    PH_CHECK_SUCCESS(status);

    // Start interrupt thread
    Set_Interrupt();

    /*
     * Set HAL type in BAL
     */
#ifdef NXPBUILD__PHHAL_HW_PN5180
    status = phbalReg_SetConfig(&sBalReader, PHBAL_REG_CONFIG_HAL_HW_TYPE, PHBAL_REG_HAL_HW_PN5180);
#endif
#ifdef NXPBUILD__PHHAL_HW_RC523
    status = phbalReg_SetConfig(&sBalReader, PHBAL_REG_CONFIG_HAL_HW_TYPE, PHBAL_REG_HAL_HW_RC523);
#endif
#ifdef NXPBUILD__PHHAL_HW_RC663
    status = phbalReg_SetConfig(&sBalReader, PHBAL_REG_CONFIG_HAL_HW_TYPE, PHBAL_REG_HAL_HW_RC663);
#endif
    PH_CHECK_SUCCESS(status);

    status = phbalReg_SetPort(&sBalReader, (uint8_t *) SPI_CONFIG);
    PH_CHECK_SUCCESS(status);

    /*
     * Open BAL
     */
    status = phbalReg_OpenPort(&sBalReader);
    PH_CHECK_SUCCESS(status);

    /*
     * Initialize the Reader HAL (Hardware Abstraction Layer) component
     */
    status = phhalHw_Nfc_IC_Init(&sHal_Nfc_Ic,
                                 sizeof(phhalHw_Nfc_Ic_DataParams_t),
                                 &sBalReader,
                                 0, bHalBufferTx, sizeof(bHalBufferTx), bHalBufferRx, sizeof(bHalBufferRx));
    PH_CHECK_SUCCESS(status);

    /*
     * Set the parameter to use the SPI interface
     */
    sHal_Nfc_Ic.sHal.bBalConnectionType = PHHAL_HW_BAL_CONNECTION_SPI;

    Configure_Device(&sHal_Nfc_Ic);

    /*
     * Set the generic pointer
     */
    pHal = &sHal_Nfc_Ic.sHal;

    /*
     * Initializing specific objects for the communication with MIFARE (R) Classic cards. The MIFARE (R) Classic card
     * is compliant of ISO 14443-3 and ISO 14443-4
     */

    /*
     * Initialize the I14443-A PAL layer
     */
    status = phpalI14443p3a_Sw_Init(&spalI14443p3a, sizeof(phpalI14443p3a_Sw_DataParams_t), &sHal_Nfc_Ic.sHal);
    PH_CHECK_SUCCESS(status);

    /*
     * Initialize the I14443-A PAL component
     */
    status = phpalI14443p4a_Sw_Init(&spalI14443p4a, sizeof(phpalI14443p4a_Sw_DataParams_t), &sHal_Nfc_Ic.sHal);
    PH_CHECK_SUCCESS(status);

    /*
     * Initialize the I14443-4 PAL component
     */
    status = phpalI14443p4_Sw_Init(&spalI14443p4, sizeof(phpalI14443p4_Sw_DataParams_t), &sHal_Nfc_Ic.sHal);
    PH_CHECK_SUCCESS(status);

    /*
     * Initialize the I14443-B PAL component
     */
    status = phpalI14443p3b_Sw_Init(&spalI14443p3b, sizeof(phpalI14443p3b_Sw_DataParams_t), &sHal_Nfc_Ic.sHal);
    PH_CHECK_SUCCESS(status);

    /*
     * Initialize the MIFARE PAL component
     */
    status = phpalMifare_Sw_Init(&spalMifare, sizeof(phpalMifare_Sw_DataParams_t), &sHal_Nfc_Ic.sHal, NULL);
    PH_CHECK_SUCCESS(status);

    /*
     * Initialize the discover component
     */
    status = phacDiscLoop_Sw_Init(&sDiscLoop, sizeof(phacDiscLoop_Sw_DataParams_t), &sHal_Nfc_Ic.sHal);
    PH_CHECK_SUCCESS(status);

    /*
     * Load profile for Discovery loop
     */
    status = LoadProfile();
    PH_CHECK_SUCCESS(status);

    status = phalMfc_Sw_Init(&salMfc, sizeof(phalMfc_Sw_DataParams_t), &spalMifare, NULL);
    PH_CHECK_SUCCESS(status);

    /*
     * Read the version of the reader IC
     */
#if defined NXPBUILD__PHHAL_HW_RC523
    status = phhalHw_Rc523_ReadRegister(&sHal_Nfc_Ic.sHal, PHHAL_HW_RC523_REG_VERSION, &bDataBuffer[0]);
#endif
#if defined NXPBUILD__PHHAL_HW_RC663
    status = phhalHw_Rc663_ReadRegister(&sHal_Nfc_Ic.sHal, PHHAL_HW_RC663_REG_VERSION, &bDataBuffer[0]);
#endif
    PH_CHECK_SUCCESS(status);

    /*
     * Return Success
     */
    return PH_ERR_SUCCESS;
}

#endif
