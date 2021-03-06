/* Code generated by cmd/cgo; DO NOT EDIT. */

/* package libimmds.so */


#line 1 "cgo-builtin-export-prolog"

#include <stddef.h> /* for ptrdiff_t below */

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; ptrdiff_t n; } _GoString_;
#endif

#endif

/* Start of preamble from import "C" comments.  */


#line 19 "libimmds.go"


#include <stdlib.h>
#include <stdio.h>

#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef _GoString_ GoString;
#endif
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif


/* Return type for OpenKey */
struct OpenKey_return {
	char* r0; /* retID */
	char* r1; /* retErr */
};
extern struct OpenKey_return OpenKey(char* c_userAndOrg, char* c_path, char* c_password);
extern char* CloseKey(char* c_ID);
extern char* RecordImmData(char* c_ID, char* c_storageGrp, char* c_key, char* c_msg);

/* Return type for GetTxID */
struct GetTxID_return {
	char* r0; /* response */
	char* r1; /* retErr */
};
extern struct GetTxID_return GetTxID(char* c_ID, char* c_storageGrp, char* c_key);

/* Return type for GetBlockByTxID */
struct GetBlockByTxID_return {
	char* r0; /* response */
	long unsigned int r1; /* rspLen */
	char* r2; /* retErr */
};
extern struct GetBlockByTxID_return GetBlockByTxID(char* c_ID, char* c_storageGrp, char* c_txID);

#ifdef __cplusplus
}
#endif
