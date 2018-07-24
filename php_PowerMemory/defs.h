#ifndef STDAFX

#define STDAFX
#define PHP_COMPILER_ID "VC15"    
#define _CRT_SECURE_NO_WARNINGS

#define INRANGE(x,a,b)		(x >= a && x <= b) 
#define getBits( x )		(INRANGE(x,'0','9') ? (x - '0') : ((x&(~0x20)) - 'A' + 0xa))
#define getByte( x )		(getBits(x[0]) << 4 | getBits(x[1]))


#endif