#pragma once

#define ZVAL_HANDLE(z, h) {			\
		zval *__z = (z);			\
		Z_LVAL_P(__z) = LONG(h);			\
		Z_TYPE_P(__z) = IS_LONG;	\
	}

#define ZVAL_POINTER(z, p) {		\
		zval *__z = (z);			\
		Z_LVAL_P(__z) = LONG(p);			\
		Z_TYPE_P(__z) = IS_LONG;	\
	}

#define RETVAL_HANDLE(h) 					ZVAL_HANDLE(return_value, h)
#define RETVAL_POINTER(h) 					ZVAL_POINTER(return_value, h)

#define RETURN_HANDLE(h) 					{ RETVAL_HANDLE(h); return; }
#define RETURN_POINTER(p) 					{ RETVAL_POINTER(p); return; }