#include <Python.h>

#include "scrypt.h"

static unsigned char getNfactor(char* blockheader) {
    int n,l = 0;
    unsigned long nTimestamp = *(unsigned int*)(&blockheader[68]);
    unsigned char minNfactor = 10;
    unsigned char maxNfactor = 30;
    unsigned char N;
    uint64_t s;

    if (nTimestamp <= 1389306217) {
        return minNfactor;
    }

    s = nTimestamp - 1389306217;
    while ((s >> 1) > 3) {
      l += 1;
      s >>= 1;
    }

    s &= 3;

    n = (l * 158 + s * 28 - 2670) / 100;

    if (n < 0) n = 0;

    N = (unsigned char) n;
    n = N > minNfactor ? N : minNfactor;
    N = n < maxNfactor ? n : maxNfactor;

    return N;
}

static PyObject *scrypt_getpowhash(PyObject *self, PyObject *args)
{
    char *output;
    PyObject *value;
    PyBytesObject *input;
    unsigned int N;
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    output = PyMem_Malloc(32);
    N = 1 << (getNfactor((char *)PyBytes_AsString((PyObject*) input)) + 1);

    scrypt_N_1_1_256((char *)PyBytes_AsString((PyObject*) input), output, N);
    Py_DECREF(input);
    value = Py_BuildValue("y#", output, 32);
    PyMem_Free(output);
    return value;
}

static PyMethodDef ScryptMethods[] = {
    { "getPoWHash", scrypt_getpowhash, METH_VARARGS, "Returns the proof of work hash using scrypt" },
    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "vtc_scrypt",
        NULL,
        -1,
        ScryptMethods,
        NULL,
        NULL,
        NULL,
        NULL
};

PyMODINIT_FUNC PyInit_vtc_scrypt(void) {
    PyObject *module = PyModule_Create(&moduledef);
    return module;
}
