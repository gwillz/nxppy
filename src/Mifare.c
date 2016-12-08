#include "Mifare.h"
#include "errors.h"
#include "nxp_helpers.h"

uint8_t CLEAR_DATA[PHAL_MFUL_WRITE_BLOCK_LENGTH];
uint8_t ident_sak;

PyObject *Mifare_init(Mifare * self, PyObject * args, PyObject * kwds)
{
    int ret;
    ret = Set_Interface_Link();
    if (handle_error(ret, InitError)) return NULL;

    Reset_reader_device();

    ret = NfcRdLibInit();
    if (handle_error(ret, InitError)) return NULL;

    //prep clear data
    int i;
    for (i=0; i<PHAL_MFUL_WRITE_BLOCK_LENGTH; i++) {
        CLEAR_DATA[i] = 0;
    }
    
    ident_sak = -1;
    
    Py_RETURN_NONE;
}

PyObject *Mifare_select(Mifare * self)
{
    phStatus_t status = 0;
    uint16_t wTagsDetected = 0;

    /*
     * Field OFF
     */
    status = phhalHw_FieldOff(pHal);
    CHECK_STATUS(status);
    if (handle_error(status, SelectError)) return NULL;
    
    /*
     * Configure Discovery loop for Poll Mode
     */
    status = phacDiscLoop_SetConfig(&sDiscLoop,
                                    PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE,
                                    PHAC_DISCLOOP_POLL_STATE_DETECTION);
    CHECK_STATUS(status);
    if (handle_error(status, SelectError)) return NULL;
    
    /*
     * Run Discovery loop
     */
    status = phacDiscLoop_Run(&sDiscLoop, PHAC_DISCLOOP_ENTRY_POINT_POLL);
    if ((status & PH_ERR_MASK) != PHAC_DISCLOOP_DEVICE_ACTIVATED) {
        if (handle_error(status, SelectError)) {
            return NULL;
        } else { // handle_error should catch everything, but if it doesn't
            return PyErr_Format(SelectError, "DiscLoop_Run command failed: %02X", (status & PH_ERR_MASK));
        }
    }
    
    /*
     * Card detected
     * Get the tag types detected info
     */
    status = phacDiscLoop_GetConfig(&sDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTagsDetected);
    if (handle_error(status, SelectError)) return NULL;

    /*
     * Check for Type A tag detection
     */
    if (PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, PHAC_DISCLOOP_POS_BIT_MASK_A)) {

        uint8_t byteBufferSize = sDiscLoop.sTypeATargetInfo.aTypeA_I3P3[0].bUidSize;
        char asciiBuffer[byteBufferSize];
        uint8_t i;

        for (i = 0; i < byteBufferSize; i++) {
            sprintf(&asciiBuffer[2 * i], "%02X", sDiscLoop.sTypeATargetInfo.aTypeA_I3P3[0].aUid[i]);
        }
        
        ident_sak = sDiscLoop.sTypeATargetInfo.aTypeA_I3P3[0].aSak;
        return PyUnicode_FromString(asciiBuffer);
        
    } else {
        return PyErr_Format(SelectError, "DISCLOOP_CHECK_ANDMASK failed: %02X", (status & PH_ERR_MASK));
    }

    Py_RETURN_NONE;
}

PyObject *Mifare_read_block(Mifare * self, PyObject * args, PyObject * kwds)
{
    uint8_t blockIdx;
    static char* kwlist[] = {"block", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "b", kwlist, &blockIdx)) {
       return NULL;
    }

    phStatus_t status = 0;

    status = phalMful_Read(&salMfc, blockIdx, bDataBuffer);
    if (handle_error(status, ReadError)) return NULL;

#if PY_MAJOR_VERSION >= 3
    return Py_BuildValue("y#", &bDataBuffer[0], MFC_BLOCK_DATA_SIZE);
#else
    return Py_BuildValue("s#", &bDataBuffer[0], MFC_BLOCK_DATA_SIZE);

#endif
}

PyObject *Mifare_read_sign(Mifare * self)
{
    const size_t bufferSize = PHAL_MFUL_SIG_LENGTH;
    uint8_t data[bufferSize];
    uint8_t *sign = data;

    phStatus_t status = 0;

    status = phalMful_ReadSign(&salMfc, '\0', &sign);
    if (handle_error(status, ReadError)) return NULL;

#if PY_MAJOR_VERSION >= 3
    return Py_BuildValue("y#", sign, bufferSize);
#else
    return Py_BuildValue("s#", sign, bufferSize);
#endif
}

PyObject *Mifare_write_block(Mifare * self, PyObject * args, PyObject * kwds)
{
    phStatus_t status = 0;
    uint8_t blockIdx;
    uint8_t *data;
    int dataLen;
    
    static char* kwlist[] = {"block", "data", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "bs#", kwlist,
                                     &blockIdx, &data, &dataLen)) {
       return NULL;
    }

    if (dataLen != PHAL_MFUL_WRITE_BLOCK_LENGTH) {
        return PyErr_Format(WriteError, "Write data MUST be specified as %d bytes", PHAL_MFUL_WRITE_BLOCK_LENGTH);
    }

    status = phalMful_Write(&salMfc, blockIdx, data);
    if (handle_error(status, WriteError)) return NULL;

    Py_RETURN_NONE;
}

PyObject *Mifare_get_identity(Mifare* self)
{
    if (ident_sak < 0)
        return PyErr_Format(ReadError, "No tag selected.");
    
    uint8_t byteBufferSize = sDiscLoop.sTypeATargetInfo.aTypeA_I3P3[0].bUidSize;
    char asciiBuffer[byteBufferSize];
    uint16_t atqa = 0x00;
    uint8_t i;

    for (i = 0; i < byteBufferSize; i++) {
        sprintf(&asciiBuffer[2 * i], "%02X", sDiscLoop.sTypeATargetInfo.aTypeA_I3P3[0].aUid[i]);
    }
    
    for (i = 0; i < PHAC_DISCLOOP_I3P3A_MAX_ATQA_LENGTH; i++) {
        atqa = atqa | sDiscLoop.sTypeATargetInfo.aTypeA_I3P3[0].aAtqa[i] << i * sizeof(uint8_t);
    }
    
#if PY_MAJOR_VERSION >= 3
    return Py_BuildValue("{s:y#, s:B, s:B}",
#else
    return Py_BuildValue("{s:s#, s:B, s:B}",
#endif
                         "uid\0",  &asciiBuffer[0], byteBufferSize * 2,
                         "atqa\0", atqa,
                         "sak\0",  ident_sak
                        );
}

PyObject *Mifare_get_version(Mifare* self)
{
    const size_t bufferSize = PHAL_MFC_VERSION_LENGTH;
    unsigned char version[bufferSize];
    
    phStatus_t status = 0;
    
    status = phalMful_GetVersion(&salMfc, version);
    if (handle_error(status, ReadError)) return NULL;
    
    return Py_BuildValue("{s:B, s:B, s:B, s:B, s:B, s:B, s:B}",
                         "vendor\0",       version[1],
                         "tag_type\0",     version[2],
                         "tag_subtype\0",  version[3],
                         "version_major\0",version[4],
                         "version_minor\0",version[5],
                         "tag_size\0",     version[6],
                         "protocol\0",     version[7]
                        );
}

PyObject* Mifare_clear_block(Mifare* self, PyObject* args, PyObject* kwds) {
    phStatus_t status = 0;
    uint8_t blockIdx;
    
    static char* kwlist[] = {"block", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "b", kwlist, &blockIdx)) {
        return NULL;
    }
    
    status = phalMful_Write(&salMfc, blockIdx, CLEAR_DATA);
    if (handle_error(status, WriteError)) return NULL;

    Py_RETURN_NONE;
}

/***********************************
** Python Type Definiton
***********************************/
PyMethodDef Mifare_methods[] = {
    {"select", (PyCFunction) Mifare_select, METH_NOARGS, "Select a Mifare card if present. Returns the card UID"}
    ,
    {"read_block", (PyCFunction) Mifare_read_block, METH_VARARGS | METH_KEYWORDS, "Read 4 bytes starting at the specified block."}
    ,
    {"read_sign", (PyCFunction) Mifare_read_sign, METH_NOARGS, "Read 32 bytes card manufacturer signature."}
    ,
    {"write_block", (PyCFunction) Mifare_write_block, METH_VARARGS | METH_KEYWORDS, "Write 4 bytes starting at the specified block."}
    ,
    {"get_version", (PyCFunction) Mifare_get_version, METH_NOARGS, "Read version data as a dict."}
    ,
    {"get_ident", (PyCFunction) Mifare_get_identity, METH_NOARGS, "Read uid, atqa, and sak as a dict."}
    ,
    {"clear_block", (PyCFunction) Mifare_clear_block, METH_VARARGS | METH_KEYWORDS, "Clear 4 bytes starting at the specifed block."}
    ,
    {NULL}                      /* Sentinel */
};

PyTypeObject MifareType = {
    PyVarObject_HEAD_INIT(NULL, 0)
        "nxppy._mifare.Mifare", /* tp_name */
    sizeof(Mifare),             /* tp_basicsize */
    0,                          /* tp_itemsize */
    0,                          /* tp_dealloc */
    0,                          /* tp_print */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_reserved */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,         /* tp_flags */
    "Mifare objects",           /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    Mifare_methods,             /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    (initproc) Mifare_init,     /* tp_init */
};
