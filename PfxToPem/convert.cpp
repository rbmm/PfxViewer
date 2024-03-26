#include "stdafx.h"

#include "pem.h"

NTSTATUS SaveToFile(_In_ PCWSTR lpFileName, _In_ const void* lpBuffer, _In_ ULONG nNumberOfBytesToWrite);
HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PBYTE* ppb, _Out_ ULONG* pcb);

HRESULT PEMImport(_In_ PCWSTR lpFileName, 
				  _In_ PCWSTR szPassword, 
				  _Out_ HCERTSTORE* phStore,
				  _Out_ ULONG* pcb);
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

typedef signed char SCHAR;

#define szOID_PKCS_12_SHROUDEDKEY_BAG "1.2.840.113549.1.12.10.1.2"

const BYTE* GetShrouedKeyBag(const BYTE* pbBuffer, ULONG cbLength, _Out_ PDATA_BLOB pdb)
{
	BOOLEAN bBag = FALSE;

	if (cbLength)
	{
		union {
			ULONG Len;
			struct {
				SCHAR l_0;
				SCHAR l_1;
				SCHAR l_2;
				SCHAR l_3;
			};
		};

		do 
		{
			const BYTE* pb = pbBuffer;
			ULONG cb = cbLength;

			union {
				ULONG uTag;
				struct {
					SCHAR t_0;
					SCHAR t_1;
					SCHAR t_2;
					SCHAR t_3;
				};
				struct {
					UCHAR tag : 5;
					UCHAR composite : 1;
					UCHAR cls : 2;
				};
			};

			uTag = *pbBuffer++, cbLength--;

			if (tag == 0x1F)
			{
				if (!cbLength--)
				{
					return 0;
				}

				if (0 > (t_1 = *pbBuffer++))
				{
					if (!cbLength--)
					{
						return 0;
					}

					if (0 > (t_2 = *pbBuffer++))
					{
						if (!cbLength--)
						{
							return 0;
						}

						t_3 = *pbBuffer++;
					}
				}
			}

			if (!uTag)
			{
				Len = 0;
				continue;
			}

			if (!cbLength--)
			{
				return 0;
			}

			Len = *pbBuffer++;

			if (0 > l_0)
			{
				if ((Len &= ~0x80) > cbLength)
				{
					return 0;
				}

				cbLength -= Len;

				switch (Len)
				{
				case 4:
					l_3 = *pbBuffer++;
					l_2 = *pbBuffer++;
				case 2:
					l_1 = *pbBuffer++;
				case 1:
					l_0 = *pbBuffer++;
				case 0:
					break;
				default: return 0;
				}
			}

			if (Len > cbLength)
			{
				return 0;
			}

			if (bBag)
			{
				bBag = FALSE;

				if (pdb->pbData)
				{
					return 0;
				}

				pdb->pbData = const_cast<PBYTE>(pbBuffer);
				pdb->cbData = Len;
			}

			ULONG cbStructInfo;
			union {
				PVOID pvStructInfo;
				PSTR* ppszObjId;
			};

			switch (uTag)
			{
			case ASN_TAG(ctUniversal, pcPrimitive, utObjectIdentifer):
				if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_OBJECT_IDENTIFIER, 
					pb, cb, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG, 0, &ppszObjId, &cbStructInfo))
				{
					bBag = !strcmp(*ppszObjId, szOID_PKCS_12_SHROUDEDKEY_BAG);

					LocalFree(ppszObjId);
				}
				break;

			case ASN_TAG(ctUniversal, pcPrimitive, utOctetString):
				if (Len > 32)
				{
					GetShrouedKeyBag(pbBuffer, Len, pdb);
				}
				break;
			}

			if (composite)
			{
				if (!GetShrouedKeyBag(pbBuffer, Len, pdb)) return 0;
			}

		} while (pbBuffer += Len, cbLength -= Len);
	}

	return pbBuffer;
}

HRESULT PfxToPem(_In_ CRYPT_DATA_BLOB* pPFX, _In_ PCWSTR pszPfxPass, _In_ PCWSTR pszPem)
{
	HRESULT hr = NTE_NOT_FOUND;

	DATA_BLOB dbPrivateKey {};

	if (GetShrouedKeyBag(pPFX->pbData, pPFX->cbData, &dbPrivateKey) && dbPrivateKey.pbData)
	{
		ULONG M, m, b;
		RtlGetNtVersionNumbers(&M, &m, &b);

		if (HCERTSTORE hStore = HR(hr, PFXImportCertStore(pPFX, pszPfxPass, 
			M < (_WIN32_WINNT_WIN10 >> 8) ? PKCS12_NO_PERSIST_KEY : PKCS12_ONLY_CERTIFICATES|PKCS12_NO_PERSIST_KEY)))
		{
			PCCERT_CONTEXT pCertContext = 0;

			ULONG cch = pPFX->cbData << 1;

			if (PSTR pbPem = new CHAR[cch])
			{
				PSTR buf = pbPem;
				union {
					int len;
					ULONG cb;
				};

				hr = STATUS_BUFFER_OVERFLOW;

				if (0 < (len = sprintf_s(buf, cch, "%s%s %s%s\r\n", _____, BEGIN, ENCRYPTED_PRIVATE_KEY, _____)))
				{
					buf += len, cch -= len;

					if (HR(hr, CryptBinaryToStringA(dbPrivateKey.pbData, dbPrivateKey.cbData, CRYPT_STRING_BASE64, buf, &(cb = cch))))
					{
						buf += cb, cch -= cb;

						hr = STATUS_BUFFER_OVERFLOW;

						if (0 < (len = sprintf_s(buf, cch, "%s%s %s%s\r\n", _____, END, ENCRYPTED_PRIVATE_KEY, _____)))
						{
							buf += cb, cch -= cb;
							hr = NOERROR;
							while (pCertContext = CertEnumCertificatesInStore(hStore, pCertContext))
							{
								if (HR(hr, CryptBinaryToStringA(pCertContext->pbCertEncoded, 
									pCertContext->cbCertEncoded, CRYPT_STRING_BASE64HEADER, buf, &(cb = cch))))
								{
									buf += cb, cch -= cb;
								}
								else
								{
									CertFreeCertificateContext(pCertContext);
									break;
								}
							}

							if (NOERROR == hr)
							{
								hr = SaveToFile(pszPem, pbPem, RtlPointerToOffset(pbPem, buf));
							}
						}
					}
				}

				delete [] pbPem;
			}

			CertCloseStore(hStore, 0);
		}
	}

	return hr;
}

HRESULT PfxToPem(_In_ PCWSTR pszFileName, 
				 _In_ PCWSTR szPassword, 
				 _In_ PCWSTR pszNewFileName,
				 _In_opt_ PCWSTR szNewPassword = 0)
{
	CRYPT_DATA_BLOB PFX;

	HRESULT hr = ReadFromFile(pszFileName, &PFX.pbData, &PFX.cbData);

	if (S_OK == hr)
	{
		if (!szNewPassword)
		{
			hr = PfxToPem(&PFX, szPassword, pszNewFileName);
		}
		else
		{
			if (HCERTSTORE hStore = HR(hr, PFXImportCertStore(&PFX, szPassword, 
				CRYPT_EXPORTABLE|PKCS12_NO_PERSIST_KEY|PKCS12_ALWAYS_CNG_KSP)))
			{
				CRYPT_DATA_BLOB NewPFX = { PFX.cbData << 1, new UCHAR[NewPFX.cbData] };

				if (NewPFX.pbData)
				{
					if (HR(hr, PFXExportCertStoreEx(hStore, &NewPFX, szNewPassword, 0, 
						EXPORT_PRIVATE_KEYS|REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)))
					{
						hr = PfxToPem(&NewPFX, szNewPassword, pszNewFileName);
					}
					delete [] NewPFX.pbData;
				}
				else
				{
					hr = E_OUTOFMEMORY;
				}

				CertCloseStore(hStore, 0);
			}
		}

		LocalFree(PFX.pbData);
	}

	return hr;
}

HRESULT PemToPfx(_In_ PCWSTR pszFileName, 
				 _In_ PCWSTR szPassword, 
				 _In_ PCWSTR pszNewFileName,
				 _In_ PCWSTR szNewPassword)
{
	ULONG cb;
	HCERTSTORE hStore;

	HRESULT hr = PEMImport(pszFileName, szPassword, &hStore, &cb);

	if (S_OK == hr)
	{
		CRYPT_DATA_BLOB NewPFX = { cb << 1, new UCHAR[NewPFX.cbData] };

		if (NewPFX.pbData)
		{
			if (HR(hr, PFXExportCertStoreEx(hStore, &NewPFX, szNewPassword, 0, 
				EXPORT_PRIVATE_KEYS|REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)))
			{
				hr = SaveToFile(pszNewFileName, NewPFX.pbData, NewPFX.cbData);
			}
			delete [] NewPFX.pbData;
		}
		else
		{
			hr = E_OUTOFMEMORY;
		}

		CertCloseStore(hStore, 0);
	}

	return hr;
}
