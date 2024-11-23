#include "stdafx.h"

#include "Pkcs.h"

inline ULONG BOOL_TO_ERROR(BOOL f)
{
	return f ? NOERROR : GetLastError();
}

NTSTATUS ImportRsaKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PCWSTR pszBlobType, _In_reads_(cb) BYTE* pb, _In_ ULONG cb)
{
	BCRYPT_ALG_HANDLE hAlgorithm;
	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, 0, 0);
	if (0 <= status)
	{
		status = BCryptImportKeyPair(hAlgorithm, 0, pszBlobType, phKey, pb, cb, 0);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

NTSTATUS ImportEccKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PCRYPT_ECC_PRIVATE_KEY_INFO p, _In_ UCHAR IsEncrypt)
{
	PCCRYPT_OID_INFO pOidInfo = CryptFindOIDInfo(IsEncrypt 
		? CRYPT_OID_INFO_OID_KEY|CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG 
		: CRYPT_OID_INFO_OID_KEY|CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, 
		p->szCurveOid, 
		CRYPT_PUBKEY_ALG_OID_GROUP_ID | CRYPT_OID_PREFER_CNG_ALGID_FLAG);

	if (!pOidInfo)
	{
		return STATUS_NOT_FOUND;
	}

	if (pOidInfo->cbSize < sizeof(CRYPT_OID_INFO) ||
		!pOidInfo->pwszCNGAlgid ||
		!pOidInfo->ExtraInfo.pbData ||
		pOidInfo->ExtraInfo.cbData < 3 * sizeof(ULONG))
	{
		return STATUS_INTERNAL_ERROR;
	}

	ULONG cbKey = p->PrivateKey.cbData;

	if (1 + (cbKey << 1) != p->PublicKey.cbData)
	{
		return STATUS_INVALID_PARAMETER;
	}

	ULONG cb = sizeof(BCRYPT_ECCKEY_BLOB) + cbKey * 3;
	PBCRYPT_ECCKEY_BLOB pecc = (PBCRYPT_ECCKEY_BLOB)alloca(cb);
	pecc->cbKey = cbKey;
	pecc->dwMagic = ((ULONG*)pOidInfo->ExtraInfo.pbData)[1] + 0x01000000;
	PBYTE pb = (PBYTE)(pecc+1);

	memcpy(pb, p->PublicKey.pbData + 1, cbKey << 1);
	memcpy(pb + (cbKey << 1), p->PrivateKey.pbData, cbKey);

	BCRYPT_ALG_HANDLE hAlgorithm;
	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, pOidInfo->pwszCNGAlgid, 0, 0);
	if (0 <= status)
	{
		status = BCryptImportKeyPair(hAlgorithm, 0, BCRYPT_ECCPRIVATE_BLOB, phKey, (PUCHAR)pecc, cb, 0);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

UCHAR IsEncryptKey(PCRYPT_ATTRIBUTES pAttributes)
{
	if (pAttributes)
	{
		if (DWORD cAttr = pAttributes->cAttr)
		{
			UCHAR Usage = 0;

			PCRYPT_ATTRIBUTE rgAttr = pAttributes->rgAttr;

			do 
			{
				if (!strcmp(szOID_KEY_USAGE, rgAttr->pszObjId))
				{
					if (DWORD cValue = rgAttr->cValue)
					{
						PCRYPT_ATTR_BLOB rgValue = rgAttr->rgValue;
						do 
						{
							ULONG cb;
							PCRYPT_BIT_BLOB KeyUsage;

							if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_KEY_USAGE, 
								rgValue->pbData, rgValue->cbData, 
								CRYPT_DECODE_NOCOPY_FLAG|CRYPT_DECODE_ALLOC_FLAG, 0, &KeyUsage, &cb))
							{
								Usage |= (*KeyUsage->pbData & 
									(CERT_KEY_ENCIPHERMENT_KEY_USAGE|CERT_DATA_ENCIPHERMENT_KEY_USAGE|CERT_ENCIPHER_ONLY_KEY_USAGE));

								if (KeyUsage->cbData > 1)
								{
									Usage |= (KeyUsage->pbData[1] & CERT_DECIPHER_ONLY_KEY_USAGE);
								}
								LocalFree(KeyUsage);
							}

						} while (rgValue++, --cValue);
					}
				}
			} while (rgAttr++, --cAttr);

			return Usage;
		}
	}

	return 0;
}

HRESULT PkcsImportPlainTextKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
							   _In_reads_(cb) BYTE* pb, 
							   _In_ ULONG cb, 
							   _Out_opt_ PULONG pcrc)
{
	PCRYPT_PRIVATE_KEY_INFO PrivateKeyInfo;

	HRESULT hr;

	if (HR(hr, CryptDecodeObjectEx(
		X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, pb, cb, 
		CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG|CRYPT_DECODE_SHARE_OID_STRING_FLAG, 
		0, &PrivateKeyInfo, &cb)))
	{
		PSTR pszObjId = PrivateKeyInfo->Algorithm.pszObjId;

		PCSTR lpszStructType = 0;

		if (!strcmp(pszObjId, szOID_RSA_RSA))
		{
			lpszStructType = CNG_RSA_PRIVATE_KEY_BLOB;
		}
		else if (!strcmp(pszObjId, szOID_ECC_PUBLIC_KEY))
		{
			lpszStructType = X509_ECC_PRIVATE_KEY;
		}
		//else if (!strcmp(pszObjId, szOID_X957_DSA) || !strcmp(pszObjId, szOID_OIWSEC_dsa))
		//{
		//	// _PkcsImportPlainTextKeyDsa
		//	// KspImportDsaPrivateKey DSS2 0x32535344
		//	lpszStructType = X509_DSS_PARAMETERS;
		//}
		else
		{
			hr = NTE_BAD_ALGID;
		}

		if (lpszStructType)
		{
			if (HR(hr, CryptDecodeObjectEx(X509_ASN_ENCODING, lpszStructType,
				PrivateKeyInfo->PrivateKey.pbData, PrivateKeyInfo->PrivateKey.cbData, 
				CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG|CRYPT_DECODE_SHARE_OID_STRING_FLAG, 0, &pb, &cb)))
			{
				switch ((ULONG_PTR)lpszStructType)
				{
				case (ULONG_PTR)CNG_RSA_PRIVATE_KEY_BLOB:
					HashKey((BCRYPT_RSAKEY_BLOB*) pb, cb, pcrc);
					hr = ImportRsaKey(phKey, BCRYPT_RSAPRIVATE_BLOB, pb, cb);
					break;

				case (ULONG_PTR)X509_ECC_PRIVATE_KEY:

					if (!reinterpret_cast<PCRYPT_ECC_PRIVATE_KEY_INFO>(pb)->szCurveOid)
					{
						union {
							PSTR szCurveOid;
							UCHAR buf[0x20 + sizeof(void*)];
						};
						ULONG cbCurveOid = sizeof(buf);

						if (!HR(hr, CryptDecodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER, 
							PrivateKeyInfo->Algorithm.Parameters.pbData, 
							PrivateKeyInfo->Algorithm.Parameters.cbData,
							CRYPT_DECODE_NOCOPY_FLAG, 0, &szCurveOid, &cbCurveOid)))
						{
							break;
						}

						reinterpret_cast<PCRYPT_ECC_PRIVATE_KEY_INFO>(pb)->szCurveOid = szCurveOid;
					}

					hr = ImportEccKey(phKey, 
						reinterpret_cast<PCRYPT_ECC_PRIVATE_KEY_INFO>(pb), 
						IsEncryptKey(PrivateKeyInfo->pAttributes));

					break;
				}

				LocalFree(pb);
			}
		}

		LocalFree(PrivateKeyInfo);
	}

	return hr;
}

struct CryptCNGMap 
{
	struct ENCODE_DECODE_PARA {
		PFN_CRYPT_ALLOC         pfnAlloc;           // OPTIONAL
		PFN_CRYPT_FREE          pfnFree;            // OPTIONAL
	};

	ULONG version;

	NTSTATUS (WINAPI * InitHash)(
		_Out_ BCRYPT_ALG_HANDLE* phAlgorithm, 
		_Out_ ULONG* pcbObjectLength,
		_In_ ULONG dwFlags);

	NTSTATUS (WINAPI *InitEncrypt)(
		_Out_ BCRYPT_ALG_HANDLE* phAlgorithm, 
		_Out_ ULONG* pcbObjectLength, 
		_In_ BYTE* pbParams, 
		_In_ ULONG cbParams
		);

	NTSTATUS (WINAPI *InitDecrypt)(
		_Out_ BCRYPT_ALG_HANDLE* phAlgorithm, 
		_Out_ ULONG* pcbObjectLength, 
		_In_ BYTE* pbParams, 
		_In_ ULONG cbParams
		);

	NTSTATUS (WINAPI *InitEncryptKey)(
		_In_ BCRYPT_ALG_HANDLE hAlgorithm,
		_Out_ BCRYPT_KEY_HANDLE* phKey,
		_Out_ BYTE* pbKeyObject, 
		_In_ ULONG cbKeyObject,
		_In_ const BYTE* pbSecret,
		_In_ ULONG cbSecret,
		_Out_ BYTE* pbParams,
		_Out_ ULONG cbParams
		);

	NTSTATUS (WINAPI *InitDecryptKey)(
		_In_ BCRYPT_ALG_HANDLE hAlgorithm,
		_Out_ BCRYPT_KEY_HANDLE* phKey,
		_Out_ BYTE* pbKeyObject, 
		_In_ ULONG cbKeyObject,
		_In_ const BYTE* pbSecret,
		_In_ ULONG cbSecret,
		_Out_ BYTE* pbParams,
		_Out_ ULONG cbParams
		);

	NTSTATUS (WINAPI *PasswordDeriveKey)(
		_In_ CryptCNGMap* map, 
		_In_ UCHAR SECRET_PREPEND,
		_In_ PCWSTR pszPassword,
		_In_ ULONG cbPassword, // wcslen(pszPassword)*sizeof(WCHAR)
		_In_opt_ CRYPT_PKCS12_PBE_PARAMS* p,
		_In_opt_ ULONG cb,
		_Out_ PBYTE pbOutput,
		_Out_ ULONG cbOutput
		);

	NTSTATUS (WINAPI *ParamsEncode)(
		_In_ const BYTE* pb, 
		_In_ ULONG cb, 
		_In_ const ENCODE_DECODE_PARA* pEncodePara,
		_Out_ BYTE** ppbEncoded,
		_Out_ ULONG* pcbEncoded
		);

	NTSTATUS (WINAPI *ParamsDecode)(
		_In_ const BYTE* pbEncoded, 
		_In_ ULONG cbEncoded, 
		_In_ const ENCODE_DECODE_PARA* pDecodePara,
		_Out_ BYTE** ppb,
		_Out_ ULONG* pcb
		);
};

void* WINAPI PkiAlloc(_In_ size_t cbSize)
{
	return LocalAlloc(LMEM_FIXED, cbSize);
}

void WINAPI PkiFree(void* pv)
{
	LocalFree(pv);
}

EXTERN_C
WINBASEAPI
BOOL
WINAPI
I_PFXDecrypt(_In_ PCSTR pszObjId, 
			 _In_ PBYTE pbParams, 
			 _In_ ULONG cbParams, 
			 _In_ PBYTE pbEncryptedKey, 
			 _In_ ULONG cbEncryptedKey, 
			 _Out_ BYTE* pbClearTextKey,
			 _Out_ DWORD* pcbClearTextKey, 
			 _In_ const void* pbSecret, 
			 _In_ ULONG cbSecret);

EXTERN_C PVOID __imp_I_PFXDecrypt = 0;

struct CRYPT_PKCS12_PBES2_PARAMS
{
	/*00*/BOOL bUTF8;
	/*04*/CHAR pszObjId[0x20];// szOID_PKCS_5_PBKDF2 "1.2.840.113549.1.5.12"
	/*24*/ULONG cbSalt;
	/*28*/UCHAR pbSalt[0x20];
	/*48*/ULONG cIterations;
	/*4c*/ULONG pad;
	/*50*/CHAR pszHMACAlgorithm[0x20];//PKCS12_PBKDF2_ID_HMAC_SHAxxx -> BCRYPT_HMAC_SHAxxx_ALG_HANDLE ("1.2.840.113549.2.*")
	/*70*/CHAR pszKeyAlgorithm[0x20]; //szOID_NIST_AESxxx_CBC "2.16.840.1.101.3.4.1.*2"
	/*90*/ULONG cbIV;
	/*94*/UCHAR pbIV[0x20];
	/*b4*/
};

HRESULT DecryptPrivateKey(_Inout_ PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO pepki, _In_ PCWSTR pszPassword)
{
	if (!__imp_I_PFXDecrypt)
	{
		if (HMODULE hmod = LoadLibraryW(L"crypt32"))
		{
			if (PVOID pv = GetProcAddress(hmod, "I_PFXDecrypt"))
			{
				__imp_I_PFXDecrypt = pv;
			}
		}
	}

	if (__imp_I_PFXDecrypt)
	{
		return BOOL_TO_ERROR(I_PFXDecrypt(pepki->EncryptionAlgorithm.pszObjId, 
			pepki->EncryptionAlgorithm.Parameters.pbData, 
			pepki->EncryptionAlgorithm.Parameters.cbData, 
			pepki->EncryptedPrivateKey.pbData, 
			pepki->EncryptedPrivateKey.cbData, 
			pepki->EncryptedPrivateKey.pbData,
			&pepki->EncryptedPrivateKey.cbData, 
			pszPassword, (1 + (ULONG)wcslen(pszPassword))* sizeof(WCHAR)));
	}

	HCRYPTOIDFUNCADDR hFuncAddr;

	if (HCRYPTOIDFUNCSET hFuncSet = CryptInitOIDFunctionSet("CryptCNGPKCS12GetMap", 0))
	{
		union {
			PVOID pvFuncAddr;
			CryptCNGMap* (WINAPI *GetPKCS12Map)();
		};

		if (CryptGetOIDFunctionAddress(hFuncSet, X509_ASN_ENCODING, 
			pepki->EncryptionAlgorithm.pszObjId, CRYPT_GET_INSTALLED_OID_FUNC_FLAG, &pvFuncAddr, &hFuncAddr))
		{
			CryptCNGMap* map = GetPKCS12Map();

			static const CryptCNGMap::ENCODE_DECODE_PARA cdp = { PkiAlloc, PkiFree };

			NTSTATUS status;

			ULONG cbParameters;

			union {
				PBYTE pbParameters;
				CRYPT_PKCS12_PBE_PARAMS* params;
				CRYPT_PKCS12_PBES2_PARAMS* paramsS2;
			};

			if (0 <= (status = map->ParamsDecode(
				pepki->EncryptionAlgorithm.Parameters.pbData,
				pepki->EncryptionAlgorithm.Parameters.cbData, 
				&cdp, &pbParameters, &cbParameters)))
			{
				ULONG cb;
				BCRYPT_ALG_HANDLE hAlgorithm;

				if (0 <= (status = map->InitDecrypt(&hAlgorithm, &cb, 
					pbParameters,
					cbParameters)))
				{
					BCRYPT_KEY_HANDLE hKey;

					PBYTE pbSecret = (PBYTE)pszPassword;
					ULONG cbSecret = (ULONG)wcslen(pszPassword);

					PBYTE pbIV = 0;
					ULONG cbIV = 0;
					BOOL bUTF8 = FALSE;

					if (!strcmp(szOID_PKCS_5_PBES2, pepki->EncryptionAlgorithm.pszObjId))
					{
						status = STATUS_BAD_DATA;

						if (sizeof(CRYPT_PKCS12_PBES2_PARAMS) != cbParameters ||
							sizeof(paramsS2->pbIV) < (cbIV = paramsS2->cbIV))
						{
							goto __0;
						}

						pbIV = paramsS2->pbIV;

						if (bUTF8 = paramsS2->bUTF8)
						{
							PSTR psz = 0;
							ULONG cch = 0;

							while(cch = WideCharToMultiByte(CP_UTF8, 0, pszPassword, cbSecret, psz, cch, 0, 0))
							{
								if (psz)
								{
									pbSecret = (PBYTE)psz;
									cbSecret = cch;
									break;
								}

								psz = (PSTR)alloca(cch);
							}
						}
					}

					if (!bUTF8)
					{
						++cbSecret *= sizeof(WCHAR);
					}

					status = map->InitDecryptKey(hAlgorithm, &hKey, 
						(PBYTE)alloca(cb), cb, pbSecret, cbSecret, pbParameters, cbParameters);

					BCryptCloseAlgorithmProvider(hAlgorithm, 0);

					if (0 <= status)
					{
						status = BCryptDecrypt(hKey, 
							pepki->EncryptedPrivateKey.pbData,
							pepki->EncryptedPrivateKey.cbData, 
							0, pbIV, cbIV, 
							pepki->EncryptedPrivateKey.pbData,
							pepki->EncryptedPrivateKey.cbData,
							&pepki->EncryptedPrivateKey.cbData, 0);

						BCryptDestroyKey(hKey);
					}
				}
__0:
				LocalFree(pbParameters);
			}

			CryptFreeOIDFunctionAddress(hFuncAddr, 0);

			return status ? HRESULT_FROM_NT(status) : STATUS_SUCCESS;
		}
	}

	return GetLastErrorEx();
}

HRESULT PkcsImportEncodedKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
							 _In_reads_(cb) BYTE* pb, 
							 _In_ ULONG cb, 
							 _In_ PCWSTR pszPassword,
							 _Out_opt_ PULONG pcrc)
{
	HRESULT hr;
	PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO pepki;
	ULONG s;
	if (HR(hr, CryptDecodeObjectEx(
		X509_ASN_ENCODING, PKCS_ENCRYPTED_PRIVATE_KEY_INFO, 
		pb, cb, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_SHARE_OID_STRING_FLAG, 0, &pepki, &s)))
	{
		if (S_OK == (hr = DecryptPrivateKey(pepki, pszPassword)))
		{
			hr = PkcsImportPlainTextKey(phKey,
				pepki->EncryptedPrivateKey.pbData,
				pepki->EncryptedPrivateKey.cbData, pcrc);
		}

		LocalFree(pepki);
	}

	return hr;
}

HRESULT PkcsImportKey(_Out_ NCRYPT_KEY_HANDLE* phKey, 
					  _In_reads_(cb) BYTE* pb, 
					  _In_ ULONG cb, 
					  _In_opt_ PCWSTR pszPassword /*= 0*/)
{
	NCRYPT_PROV_HANDLE hProvider;
	SECURITY_STATUS status = NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0);

	if (NOERROR == status)
	{
		NCryptBufferDesc *pParameterList = 0;
		BCryptBuffer buf;
		NCryptBufferDesc ParameterList { NCRYPTBUFFER_VERSION, 1, &buf };

		if (pszPassword)
		{
			buf.BufferType = NCRYPTBUFFER_PKCS_SECRET;
			buf.cbBuffer = (1 + (ULONG)wcslen(pszPassword)) * sizeof(WCHAR);
			buf.pvBuffer = const_cast<PWSTR>(pszPassword);

			pParameterList = &ParameterList;
		}

		NCRYPT_KEY_HANDLE hKey;

		status = NCryptImportKey(hProvider, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, 
			pParameterList, &hKey, pb, cb, NCRYPT_DO_NOT_FINALIZE_FLAG);

		NCryptFreeObject(hProvider);

		if (NOERROR == status)
		{
			static const ULONG flags = NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;

			if (NOERROR == (status = NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&flags, sizeof(flags), 0)) &&
				NOERROR == (status = NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG)))
			{
				*phKey = hKey;

				return NOERROR;
			}

			NCryptFreeObject(hKey);
		}
	}

	return status;
}

HRESULT NKeyToBKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
				   _In_ NCRYPT_KEY_HANDLE hKey, 
				   _Out_opt_ PULONG pcrc)
{
	WCHAR szAlgId[0x40];
	ULONG cb = sizeof(szAlgId);

	HRESULT status = NCryptGetProperty(hKey, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)szAlgId, sizeof(szAlgId), &cb, 0);

	if (NOERROR == status)
	{
		cb = 0;
		PBYTE pb = 0;

		while(NOERROR == (status = NCryptExportKey(hKey, 0, BCRYPT_PRIVATE_KEY_BLOB, 0, pb, cb, &cb, 0)))
		{
			if (pb)
			{
				HashKey((BCRYPT_RSAKEY_BLOB*)pb, cb, pcrc);

				BCRYPT_ALG_HANDLE hAlgorithm;
				if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, szAlgId, 0, 0)))
				{
					status = BCryptImportKeyPair(hAlgorithm, 0, BCRYPT_PRIVATE_KEY_BLOB, phKey, pb, cb, 0);
					BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				}

				break;
			}

			pb = (PBYTE)alloca(cb);
		}
	}

	return status;
}

HRESULT PkcsImportKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
					  _In_reads_(cb) BYTE* pb, 
					  _In_ ULONG cb,
					  _In_ PCWSTR pszPassword,
					  _Out_opt_ PULONG pcrc)
{
	HRESULT hr;
	NCRYPT_KEY_HANDLE hKey;
	if (S_OK == (hr = PkcsImportKey(&hKey, pb, cb, pszPassword)))
	{
		hr = NKeyToBKey(phKey, hKey, pcrc);
		NCryptFreeObject(hKey);
	}

	return hr;
}