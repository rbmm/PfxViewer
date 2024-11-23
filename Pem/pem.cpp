#include "stdafx.h"

#include "Pkcs.h"

extern const volatile UCHAR guz = 0;

class __declspec(novtable) Pem
{
	virtual HRESULT process(_In_reads_(cb) BYTE* pb, _In_ ULONG cb) = 0;

public:
	virtual ~Pem() = default;

	HRESULT import(_In_reads_(cch) PCSTR psz, _In_ ULONG cch)
	{
		HRESULT hr;

		PBYTE pb = 0;
		ULONG cb = 0;

		while (HR(hr, CryptStringToBinaryA(psz, cch, CRYPT_STRING_BASE64, pb, &cb, 0, 0)))
		{
			if (pb)
			{
				hr = process(pb, cb);
				break;
			}

			if (!(pb = new UCHAR[cb]))
			{
				hr = E_OUTOFMEMORY;
				break;
			}
		}

		if (pb) delete [] pb;

		return hr;
	}

	void* operator new(size_t s, void* pv, ULONG cb)
	{
		return cb < s ? 0 : pv;
	}

	void operator delete (void* /*pv*/)
	{
	}
};

class PemCert : public Pem
{
	HCERTSTORE _M_hCertStore;

	virtual HRESULT process(_In_reads_(cb) BYTE* pb, _In_ ULONG cb)
	{
		HRESULT hr;
		HR(hr, CertAddEncodedCertificateToStore(_M_hCertStore, X509_ASN_ENCODING, pb, cb, CERT_STORE_ADD_NEW, 0));
		return hr;
	}

public:

	PemCert(HCERTSTORE hCertStore) : _M_hCertStore(hCertStore)
	{
	}
};

class __declspec(novtable) PemKey : public Pem
{
protected:

	BCRYPT_KEY_HANDLE _M_hKey = 0;

	virtual ~PemKey()
	{
		if (_M_hKey)
		{
			BCryptDestroyKey(_M_hKey);
		}
	}
public:

	BCRYPT_KEY_HANDLE get()
	{
		BCRYPT_KEY_HANDLE hKey = _M_hKey;
		_M_hKey = 0;
		return hKey;
	}
};

struct __declspec(novtable) PemRsaKey : public PemKey
{
	virtual PCSTR GetStructType() = 0;

	virtual PCWSTR GetBlobType() = 0;

	virtual HRESULT process(_In_reads_(cb) BYTE* pb, _In_ ULONG cb)
	{
		HRESULT hr;
		if (HR(hr, CryptDecodeObjectEx(X509_ASN_ENCODING, GetStructType(), pb, cb, 
			CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG|CRYPT_DECODE_SHARE_OID_STRING_FLAG, 0, &pb, &cb)))
		{
			hr = ImportRsaKey(&_M_hKey, GetBlobType(), pb, cb);

			LocalFree(pb);
		}

		return hr;
	}
};

struct PemRsaPublicKey : public PemRsaKey
{
	virtual PCSTR GetStructType() 
	{
		return CNG_RSA_PUBLIC_KEY_BLOB;
	}

	virtual PCWSTR GetBlobType()
	{
		return BCRYPT_RSAPUBLIC_BLOB;
	}
};

struct PemRsaPrivateKey : public PemRsaKey
{
	virtual PCSTR GetStructType() 
	{
		return CNG_RSA_PRIVATE_KEY_BLOB;
	}

	virtual PCWSTR GetBlobType()
	{
		return BCRYPT_RSAPRIVATE_BLOB;
	}
};

struct PemPublicKey : public PemKey
{
	virtual HRESULT process(_In_reads_(cb) BYTE* pb, _In_ ULONG cb)
	{
		HRESULT hr;
		PCERT_PUBLIC_KEY_INFO PublicKeyInfo;

		if (HR(hr, CryptDecodeObjectEx(X509_ASN_ENCODING, 
			X509_PUBLIC_KEY_INFO, pb, cb, 
			CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG|CRYPT_DECODE_SHARE_OID_STRING_FLAG, 
			0, &PublicKeyInfo, &cb)))
		{
			HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, PublicKeyInfo, 0, 0, &_M_hKey));

			LocalFree(PublicKeyInfo);
		}

		return hr;
	}
};

struct PemPrivateKey : public PemKey
{
	virtual HRESULT process(_In_reads_(cb) BYTE* pb, _In_ ULONG cb)
	{
		return PkcsImportPlainTextKey(&_M_hKey, pb, cb);
	}
};

struct PemEncryptedPrivateKey : public PemPrivateKey
{
	PCWSTR _M_pszPassword;

	PemEncryptedPrivateKey(PCWSTR pszPassword) : _M_pszPassword(pszPassword)
	{
	}

	virtual HRESULT process(_In_reads_(cb) BYTE* pb, _In_ ULONG cb)
	{
		return PkcsImportEncodedKey(&_M_hKey, pb, cb, _M_pszPassword);
	}
};

//////////////////////////////////////////////////////////////////////////

BOOLEAN IsCertMatch(_In_ PCCERT_CONTEXT pCertContext, _In_ ULONG crc)
{
	HRESULT hr;
	BCRYPT_KEY_HANDLE hKey;

	if (HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &pCertContext->pCertInfo->SubjectPublicKeyInfo, 0, 0, &hKey)))
	{
		PBYTE pb = 0;
		ULONG cb = 0;

		while (STATUS_SUCCESS == (hr = BCryptExportKey(hKey, 0, BCRYPT_PUBLIC_KEY_BLOB, pb, cb, &cb, 0)))
		{
			if (pb)
			{
				crc -= RtlComputeCrc32(0, pb, cb);
				break;
			}

			pb = (PBYTE)alloca(cb);
		}

		BCryptDestroyKey(hKey);
	}

	return !crc;
}

HRESULT GetPublicCrc(_In_ BCRYPT_KEY_HANDLE hKey, _Out_ ULONG* crc)
{
	ULONG cb = 0;
	PBYTE pb = 0;

	HRESULT hr;

	while (NOERROR == (hr = BCryptExportKey(hKey, 0, BCRYPT_PUBLIC_KEY_BLOB, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			*crc = RtlComputeCrc32(0, pb, cb);

			return NOERROR;
		}

		pb = (PBYTE)alloca(cb);
	}

	return hr;
}

PSTR __fastcall strnstr(SIZE_T n1, const void* str1, SIZE_T n2, const void* str2);

#define _strnstr(a, b, x) strnstr(RtlPointerToOffset(a, b), a, sizeof(x) - 1, x)

PCSTR IsTag(_In_ PCSTR buf, _In_ PCSTR end, _In_ PCSTR TAG, _In_ ULONG cb)
{
	return (ULONG_PTR)(end - buf) < cb || memcmp(buf, TAG, cb) ? 0 : buf + cb;
}

PCSTR IsBegin(_In_ PCSTR buf, _In_ PCSTR end)
{
	const static char BEGIN[] = "BEGIN";
	return IsTag(buf, end, BEGIN, sizeof(BEGIN) - 1);
}

PCSTR IsEnd(_In_ PCSTR buf, _In_ PCSTR end)
{
	const static char END[] = "END";
	return IsTag(buf, end, END, sizeof(END) - 1);
}

void FreeKeysI(_In_ BCRYPT_KEY_HANDLE* phKeys, _In_ ULONG nKeys)
{
	if (nKeys)
	{
		do 
		{
			BCryptDestroyKey(*phKeys++);
		} while (--nKeys);
	}
}

void FreeKeys(_In_ BCRYPT_KEY_HANDLE* phKeys, _In_ ULONG nKeys)
{
	FreeKeysI(phKeys, nKeys);
	LocalFree(phKeys);
}

HRESULT PEMImport(_Out_ HCERTSTORE* phStore,
				  _Out_ BCRYPT_KEY_HANDLE** pphKeys,
				  _Out_ ULONG* pnKeys,
				  _In_ PCSTR buf, 
				  _In_ PCSTR end,
				  _In_ PCWSTR pszPassword)
{
	const static char _____[] = "-----";
	const static char ENCRYPTED_PRIVATE_KEY[] = "ENCRYPTED PRIVATE KEY";
	const static char CERTIFICATE[] = "CERTIFICATE";

	enum { fInvalid ,fCert, fEncPrivKey, fPrivKey, fPubKey, fRsaPubKey, fRsaPrivKey } bt;

	*pphKeys = 0;
	*phStore = 0;
	*pnKeys = 0;

	HRESULT hr;
	PVOID stack = alloca(guz);
	BCRYPT_KEY_HANDLE* keys = (BCRYPT_KEY_HANDLE*)stack;
	ULONG nKeys = 0, nCerts = 0;

	if (HCERTSTORE hStore = HR(hr, CertOpenStore(sz_CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)))
	{
		while (buf = _strnstr(buf, end, _____))
		{
			hr = HRESULT_FROM_NT(STATUS_INVALID_IMAGE_FORMAT);

			bt = fInvalid;

			if (!(buf = IsBegin(buf, end - sizeof(_____))) || *buf++ != ' ')
			{
				break;
			}

			PCSTR pcTag = buf;

			if (buf = IsTag(pcTag, end, CERTIFICATE, sizeof(CERTIFICATE) - 1))
			{
				bt = fCert;
			}
			else if (buf = IsTag(pcTag, end, 
				ENCRYPTED_PRIVATE_KEY + _countof("ENCRYPTED"), 
				sizeof(ENCRYPTED_PRIVATE_KEY) - _countof("ENCRYPTED") - 1))
			{
				bt = fPrivKey;
			}
			else if (buf = IsTag(pcTag, end, ENCRYPTED_PRIVATE_KEY, sizeof(ENCRYPTED_PRIVATE_KEY) - 1))
			{
				bt = fEncPrivKey;
			}
			else
			{
				if (!(buf = _strnstr(pcTag, end - 2, _____)))
				{
					break;
				}
				goto __0;
			}

			if (!(buf = IsTag(buf, end - 2, _____, sizeof(_____) - 1)))
			{
				break;
			}

__0:
			ULONG len = RtlPointerToOffset(pcTag, buf);

			PCSTR pc = buf;

			if (!(buf = _strnstr(buf, end, _____)))
			{
				break;
			}

			ULONG cb = RtlPointerToOffset(pc, buf - sizeof(_____));

			if (!(buf = IsEnd(buf, end - sizeof(_____))) || 
				*buf++ != ' ' ||
				!(buf = IsTag(buf, end, pcTag, len)))
			{
				break;
			}

			UCHAR pembuf[sizeof(PemEncryptedPrivateKey)];
			Pem* pem = 0;

			switch (bt)
			{
			case fCert:
				pem = new(pembuf, sizeof(pembuf)) PemCert(hStore);
				break;

			case fPrivKey:
				pem = new(pembuf, sizeof(pembuf)) PemPrivateKey;
				break;

			case fEncPrivKey:
				pem = new(pembuf, sizeof(pembuf)) PemEncryptedPrivateKey(pszPassword);
				break;
			}

			if (pem)
			{
				if (S_OK == (hr = pem->import(pc, cb)))
				{
					if (fCert == bt)
					{
						nCerts++;
					}
					else
					{
						if (--keys < stack)
						{
							stack = alloca(sizeof(Pem*));
						}

						*keys = static_cast<PemKey*>(pem)->get();

						if (++nKeys == 128)
						{
							hr = STATUS_TOO_MANY_SECRETS;
						}
					}
				}

				delete pem;
			}

			if (hr)
			{
				break;
			}
		}

		if (S_OK == hr)
		{
			if (!nKeys && !nCerts)
			{
				hr = STATUS_NOT_FOUND;
			}
			else
			{
				if (nKeys)
				{
					if (PVOID pv = HR(hr, LocalAlloc(LMEM_FIXED, nKeys * sizeof(BCRYPT_KEY_HANDLE))))
					{
						*pphKeys = (BCRYPT_KEY_HANDLE *)memcpy(pv, keys, nKeys * sizeof(BCRYPT_KEY_HANDLE));
						*pnKeys = nKeys;
					}
				}

				if (S_OK == hr)
				{
					*phStore = hStore;
					return S_OK;
				}
			}
		}

		FreeKeysI(keys, nKeys);
		CertCloseStore(hStore, 0);
	}

	return hr;
}

HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PBYTE* ppb, _Out_ ULONG* pcb);

HRESULT PEMImport(_Out_ HCERTSTORE* phStore,
				  _Out_ BCRYPT_KEY_HANDLE** pphKeys,
				  _Out_ ULONG* pnKeys,
				  _In_ PCWSTR pszFileName,
				  _In_ PCWSTR pszPassword)
{
	PSTR pb;
	ULONG cb;
	HRESULT hr = ReadFromFile(pszFileName, (PBYTE*)&pb, &cb);
	if (S_OK == hr)
	{
		hr = PEMImport(phStore, pphKeys, pnKeys, pb, pb + cb, pszPassword);
		LocalFree(pb);
	}

	return hr;
}

HRESULT GetCertForKey(_Out_ PCCERT_CONTEXT* ppCertContext,
					  _In_ HCERTSTORE hStore,
					  _In_ BCRYPT_KEY_HANDLE hKey)
{
	ULONG crc;
	HRESULT hr = GetPublicCrc(hKey, &crc);

	if (hr)
	{
		return hr;
	}

	PCCERT_CONTEXT pCertContext = 0;

	while (pCertContext = HR(hr, CertEnumCertificatesInStore(hStore, pCertContext)))
	{
		if (IsCertMatch(pCertContext, crc))
		{
			*ppCertContext = pCertContext;
			return NOERROR;
		}
	}

	return hr;
}