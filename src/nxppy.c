#include <Python.h>
#include "Mifare.h"

PyObject *InitError;
PyObject *SelectError;
PyObject *ReadError;
PyObject *WriteError;

/*
 * ########################################################### # Python Extension definitions
 * ###########################################################
 */
#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "nxppy._mifare",
    NULL,
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

#define INITERROR return NULL

PyObject *PyInit__mifare(void)
#else
#define INITERROR return

PyMethodDef nxppy_methods[] = {
    {NULL, NULL}
    ,
};

void init_mifare(void)
#endif
{
    PyObject *module;

    MifareType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&MifareType) < 0) {
        INITERROR;
    }
    
#if PY_MAJOR_VERSION >= 3
    module = PyModule_Create(&moduledef);
#else
    module = Py_InitModule("nxppy._mifare", nxppy_methods);
#endif

    if (module == NULL)
        INITERROR;

    Py_INCREF(&MifareType);
    PyModule_AddObject(module, "Mifare", (PyObject *) & MifareType);

    InitError = PyErr_NewException("nxppy._mifare.InitError", NULL, NULL);
    Py_INCREF(InitError);
    PyModule_AddObject(module, "InitError", InitError);

    SelectError = PyErr_NewException("nxppy._mifare.SelectError", NULL, NULL);
    Py_INCREF(SelectError);
    PyModule_AddObject(module, "SelectError", SelectError);

    ReadError = PyErr_NewException("nxppy._mifare.ReadError", NULL, NULL);
    Py_INCREF(ReadError);
    PyModule_AddObject(module, "ReadError", ReadError);

    WriteError = PyErr_NewException("nxppy._mifare.WriteError", NULL, NULL);
    Py_INCREF(WriteError);
    PyModule_AddObject(module, "WriteError", WriteError);

#if PY_MAJOR_VERSION >= 3
    return module;
#endif
}
