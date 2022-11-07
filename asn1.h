#pragma once

//==============================================================================
//
// ASN.1 constructs
//
//==============================================================================

#define ASN_TAG(c, p, t) ((ULONG)( static_cast<int>(c) | static_cast<int>(p) | static_cast<int>(t) ))
#define ASN_INDEX(i)	ASN_TAG(ctContextSpecific, pcConstructed, i)
#define SEQUENCE		ASN_TAG(ctUniversal, pcConstructed, utSequence)
#define ASN_APP(a)		ASN_TAG(ctApplication, pcConstructed, a)
#define ASN_DATA(t)		ASN_TAG(ctUniversal, pcPrimitive, t)

//
// Class tags
//

enum ClassTag
{
	ctUniversal          =  0x00, // 00000000
	ctApplication        =  0x40, // 01000000
	ctContextSpecific    =  0x80, // 10000000
	ctPrivate            =  0xC0, // 11000000
};

//
// Primitive-Constructed
//

enum PC
{
	pcPrimitive          = 0x00, // 00000000
	pcConstructed        = 0x20, // 00100000
};

enum UniversalTag
{
	utBoolean            = 0x01, // 00001
	utInteger            = 0x02, // 00010
	utBitString          = 0x03, // 00011
	utOctetString        = 0x04, // 00100
	utNULL               = 0x05, // 00101
	utObjectIdentifer    = 0x06, // 00110
	utObjectDescriptor   = 0x07, // 00111
	utExternal           = 0x08, // 01000
	utReal               = 0x09, // 01001
	utEnumerated         = 0x0A, // 01010
	utSequence           = 0x10, // 10000
	utSet                = 0x11, // 10001
	utNumericString      = 0x12, // 10010
	utPrintableString    = 0x13, // 10011
	utT61String          = 0x14, // 10100
	utVideotexString     = 0x15, // 10101
	utIA5String          = 0x16, // 10110
	utUTCTime            = 0x17, // 10111
	utGeneralizedTime    = 0x18, // 11000
	utGraphicString      = 0x19, // 11001
	utVisibleString      = 0x1A, // 11010
	utGeneralString      = 0x1B, // 11011
	utUniversalString    = 0x1C,
	utCharString         = 0x1D,
	utBMPString          = 0x1E,
};

