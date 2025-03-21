
#ifndef PKCS11_H
#define PKCS11_H

#include <stdio.h>
#include <string.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "oasis/pkcs11.h"

#endif