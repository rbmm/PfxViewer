#include "stdafx.h"
#include "..\NtVer\nt_ver.h"

_NT_BEGIN

#include "asn1.h"

struct SC
{
	NCRYPT_KEY_HANDLE _hKey = 0;
	PCWSTR pcszPassword;
	SECURITY_STATUS opStatus = STATUS_NOT_FOUND;
	ULONG cbData;

	SC(PCWSTR pcszPassword) : pcszPassword(pcszPassword)
	{
	}

	~SC()
	{
		if (NCRYPT_HANDLE hObject = _hKey)
		{
			NCryptFreeObject(hObject);
		}
	}

	BOOLEAN ImportKey(PUCHAR pb, ULONG cb);

	LPCBYTE GetPriv8Key(LPCBYTE pbBuffer, ULONG cbLength);
};

BOOLEAN SC::ImportKey(PUCHAR pb, ULONG cb)
{
	if (_hKey)
	{
		opStatus = RPC_NT_ENTRY_ALREADY_EXISTS;
		return FALSE;
	}

	NCRYPT_PROV_HANDLE hProvider;
	SECURITY_STATUS status = NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0);

	if (!status)
	{
		PCWSTR pcsz = pcszPassword;

		NCryptBuffer buf = { 
			(1 + (ULONG)wcslen(pcsz)) * sizeof(WCHAR), NCRYPTBUFFER_PKCS_SECRET, const_cast<PWSTR>(pcsz) 
		};

		NCryptBufferDesc ParameterList { NCRYPTBUFFER_VERSION, 1, &buf };

		NCRYPT_KEY_HANDLE hKey;

		status = NCryptImportKey(hProvider, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, 
			&ParameterList, &hKey, pb, cb, NCRYPT_DO_NOT_FINALIZE_FLAG);

		NCryptFreeObject(hProvider);

		if (!status)
		{
			static const ULONG Flags = NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;

			if ((status = NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&Flags, sizeof(Flags), 0)) ||
				(status = NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG)))
			{
				NCryptFreeObject(hKey);
			}
			else
			{
				_hKey  = hKey;
			}
		}
	}

	opStatus = status;

	return !status;
}

LPCBYTE SC::GetPriv8Key(LPCBYTE pbBuffer, ULONG cbLength)
{
	bool bDecrypt = false;

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
			LPCBYTE pb = pbBuffer;
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

			if (bDecrypt)
			{
				bDecrypt = FALSE;

				if (!ImportKey(const_cast<PUCHAR>(pbBuffer), Len))
				{
					return 0;
				}
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
					bDecrypt = !strcmp(*ppszObjId, "1.2.840.113549.1.12.10.1.2");

					LocalFree(ppszObjId);
				}
				break;

			case ASN_TAG(ctUniversal, pcPrimitive, utOctetString):
				if (Len > 32)
				{
					GetPriv8Key(pbBuffer, Len);
				}
				break;
			}

			if (composite)
			{
				if (!GetPriv8Key(pbBuffer, Len)) return 0;
			}

		} while (pbBuffer += Len, cbLength -= Len);
	}

	return pbBuffer;
}

BOOLEAN IsCertMatchEcc(_In_ PCCERT_CONTEXT pCertContext, _In_ PVOID pvKeyData, _In_ ULONG cbKeyData)
{
	if (pCertContext)
	{
		PCRYPT_BIT_BLOB PublicKey = &pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey;

		return PublicKey->cbData == cbKeyData + 1 && !memcmp(1 + PublicKey->pbData, pvKeyData, cbKeyData);
	}

	return TRUE;
}

BOOLEAN IsCertMatchRsa(_In_ PCCERT_CONTEXT pCertContext, _In_ PVOID pvKeyData, _In_ ULONG BitLength)
{
	if (!pCertContext)
	{
		return TRUE;
	}

	PCRYPT_BIT_BLOB PublicKey = &pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey;

	ULONG cb;
	BCRYPT_RSAKEY_BLOB* prkb;

	if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB, 
		PublicKey->pbData, PublicKey->cbData, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG, 
		0, &prkb, &cb))
	{
		BOOLEAN b = cb > sizeof(BCRYPT_RSAKEY_BLOB) &&
			prkb->BitLength == BitLength &&
			!memcmp(prkb + 1, pvKeyData, cb - sizeof(BCRYPT_RSAKEY_BLOB));

		LocalFree(prkb);

		return b;
	}

	return FALSE;
}

HRESULT PFXImport(_In_ PUCHAR pbPFX, 
				  _In_ ULONG cbPFX, 
				  _In_ PCWSTR szPassword, 
				  _Out_ PCCERT_CONTEXT* ppCertContext)
{
	SC sc(szPassword);
	if (!sc.GetPriv8Key(pbPFX, cbPFX) )
	{
		return OSS_DATA_ERROR;
	}

	if (sc.opStatus)
	{
		return HRESULT_FROM_WIN32(sc.opStatus);
	}

	union {
		BCRYPT_RSAKEY_BLOB* prkb;
		PBCRYPT_ECCKEY_BLOB pecc;
		BCRYPT_KEY_BLOB* pkb;
		PVOID pv;
		PBYTE pb = 0;
	};

	ULONG cb = 0;

	HRESULT hr;
	NCRYPT_KEY_HANDLE hKey = sc._hKey;

	while(NOERROR == (hr = NCryptExportKey(hKey, 0, BCRYPT_PUBLIC_KEY_BLOB, 0, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			ULONG cbKeyData = prkb->BitLength;
			PVOID pvKeyData = prkb + 1;

			BOOLEAN (*IsCertMatch)(_In_ PCCERT_CONTEXT pCertContext, _In_ PVOID pvKeyData, _In_ ULONG cbKeyData);

			switch (pkb->Magic)
			{
			case BCRYPT_RSAPUBLIC_MAGIC:
				IsCertMatch = IsCertMatchRsa;
				cbKeyData = prkb->BitLength;
				pvKeyData = prkb + 1;
				break;

			case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
			case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
			case BCRYPT_ECDSA_PUBLIC_P521_MAGIC:
				IsCertMatch = IsCertMatchEcc;
				cbKeyData = pecc->cbKey << 1;
				pvKeyData = pecc + 1;
				break;

			default:
				return HRESULT_FROM_NT(STATUS_NOT_SUPPORTED);
			}

			DATA_BLOB pfx = { cbPFX, pbPFX };

			if (HCERTSTORE hStore = PFXImportCertStore(&pfx, szPassword,
				g_nt_ver.Version < _WIN32_WINNT_WIN10 ? PKCS12_NO_PERSIST_KEY : PKCS12_ONLY_CERTIFICATES|PKCS12_NO_PERSIST_KEY))
			{
				PCCERT_CONTEXT pCertContext = 0;

				while (!IsCertMatch(pCertContext = CertEnumCertificatesInStore(hStore, pCertContext), pvKeyData, cbKeyData)) ;

				CertCloseStore(hStore, 0);

				if (pCertContext)
				{
					*ppCertContext = pCertContext;

					return S_OK;
				}

				return HRESULT_FROM_NT(STATUS_NOT_FOUND);

			}

			return HRESULT_FROM_WIN32(GetLastError());
		}

		pv = alloca(cb);
	}

	return hr;
}

HRESULT GetLastErrorEx(ULONG dwError = GetLastError())
{
	NTSTATUS status = RtlGetLastNtStatus();
	return dwError == RtlNtStatusToDosErrorNoTeb(status) ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

HRESULT PFXImport(_In_ PCWSTR lpFileName, 
				  _In_ PCWSTR szPassword, 
				  _Out_ PCCERT_CONTEXT* ppCertContext)
{
	HANDLE hFile = CreateFileW(lpFileName, FILE_GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);

	if (!hFile)
	{
		return GetLastErrorEx();
	}

	ULONG f = FACILITY_NT_BIT;

	FILE_STANDARD_INFORMATION fsi;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);

	if (0 <= status)
	{
		if (fsi.EndOfFile.QuadPart - 0x100 > MAXUSHORT)
		{
			status = STATUS_FILE_TOO_LARGE;
		}
		else
		{
			if (PUCHAR pbPFX = new UCHAR [fsi.EndOfFile.LowPart])
			{
				if (0 <= (status = NtReadFile(hFile, 0, 0, 0, &iosb, pbPFX, fsi.EndOfFile.LowPart, 0, 0)))
				{
					f = 0;
					status = PFXImport(pbPFX, (ULONG)iosb.Information, szPassword, ppCertContext);
				}

				delete [] pbPFX;
			}
		}
	}

	NtClose(hFile);

	return status ? status | f : S_OK;
}

_NT_END