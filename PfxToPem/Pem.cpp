#include "stdafx.h"

PSTR __fastcall strnstr(SIZE_T n1, const void* str1, SIZE_T n2, const void* str2);

#define _strnstr(a, b, x) strnstr(RtlPointerToOffset(a, b), a, sizeof(x) - 1, x)

HRESULT PkcsImportKey(_Out_ NCRYPT_KEY_HANDLE* phKey, _In_reads_(cb) BYTE* pb, _In_ ULONG cb, _In_opt_ PCWSTR pszPassword = 0)
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

HRESULT GetPublicCrc(_In_ NCRYPT_KEY_HANDLE hKey, _Out_ ULONG* crc)
{
	ULONG cb = 0;
	PBYTE pb = 0;

	HRESULT hr;

	while (NOERROR == (hr = NCryptExportKey(hKey, 0, BCRYPT_PUBLIC_KEY_BLOB, 0, pb, cb, &cb, 0)))
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

HRESULT AssignKeys(_Inout_ NCRYPT_KEY_HANDLE* phKeys, 
				   _In_ ULONG nKeys, 
				   _Inout_ HCERTSTORE hStore)
{
	CERT_KEY_CONTEXT ckc = { sizeof(CERT_KEY_CONTEXT), { }, CERT_NCRYPT_KEY_SPEC };
	do 
	{
		ULONG crc;
		HRESULT hr = GetPublicCrc(ckc.hCryptProv = *phKeys, &crc);

		if (hr)
		{
			return hr;
		}

		PCCERT_CONTEXT pCertContext = 0;

		while (pCertContext = HR(hr, CertEnumCertificatesInStore(hStore, pCertContext)))
		{
			if (IsCertMatch(pCertContext, crc))
			{
				if (HR(hr, CertSetCertificateContextProperty(pCertContext, 
					CERT_KEY_CONTEXT_PROP_ID, 0, &ckc)))
				{
					*phKeys = 0;
				}
				else
				{
					CertFreeCertificateContext(pCertContext);
					return hr;
				}
			}
		}

	} while (phKeys++, --nKeys);

	return NOERROR;
}

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

	NCRYPT_KEY_HANDLE _M_hKey = 0;

	virtual ~PemKey()
	{
		if (_M_hKey)
		{
			NCryptFreeObject(_M_hKey);
		}
	}
public:

	NCRYPT_KEY_HANDLE get()
	{
		NCRYPT_KEY_HANDLE hKey = _M_hKey;
		_M_hKey = 0;
		return hKey;
	}
};

struct PemPrivateKey : public PemKey
{
	virtual HRESULT process(_In_reads_(cb) BYTE* pb, _In_ ULONG cb)
	{
		return PkcsImportKey(&_M_hKey, pb, cb);
	}
};

struct PemEncryptedPrivateKey : public PemKey
{
	PCWSTR _M_pszPassword;

	PemEncryptedPrivateKey(PCWSTR pszPassword) : _M_pszPassword(pszPassword)
	{
	}

	virtual HRESULT process(_In_reads_(cb) BYTE* pb, _In_ ULONG cb)
	{
		return PkcsImportKey(&_M_hKey, pb, cb, _M_pszPassword);
	}
};

#include "pem.h"

extern const char _____[] = "-----";
extern const char ENCRYPTED_PRIVATE_KEY[] = "ENCRYPTED PRIVATE KEY";
extern const char CERTIFICATE[] = "CERTIFICATE";
extern const char BEGIN[] = "BEGIN";
extern const char END[] = "END";

PCSTR IsTag(_In_ PCSTR buf, _In_ PCSTR end, _In_ PCSTR TAG, _In_ ULONG cb)
{
	return (ULONG_PTR)(end - buf) < cb || memcmp(buf, TAG, cb) ? 0 : buf + cb;
}

PCSTR IsBegin(_In_ PCSTR buf, _In_ PCSTR end)
{
	return IsTag(buf, end, BEGIN, sizeof(BEGIN) - 1);
}

PCSTR IsEnd(_In_ PCSTR buf, _In_ PCSTR end)
{
	return IsTag(buf, end, END, sizeof(END) - 1);
}

HRESULT PEMImport(_Out_ HCERTSTORE* phStore,
				  _In_ PCSTR buf, 
				  _In_ PCSTR end,
				  _In_ PCWSTR pszPassword)
{
	enum { fInvalid ,fCert, fEncPrivKey, fPrivKey, fPubKey, fRsaPubKey, fRsaPrivKey } bt;

	HRESULT hr;
	PVOID stack = alloca(guz);
	NCRYPT_KEY_HANDLE* keys = (NCRYPT_KEY_HANDLE*)stack;
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

		if (S_OK == hr && !nCerts)
		{
			hr = NTE_NOT_FOUND;
		}

		if (nKeys)
		{
			if (nCerts)
			{
				if (S_OK == hr)
				{
					hr = AssignKeys(keys, nKeys, hStore);
				}
			}

			do 
			{
				if (NCRYPT_KEY_HANDLE hKey = *keys++)
				{
					NCryptFreeObject(hKey);
				}

			} while (--nKeys);
		}
		else
		{
			hr = NTE_NOT_FOUND;
		}

		if (S_OK == hr)
		{
			*phStore = hStore;

			return S_OK;
		}

		CertCloseStore(hStore, 0);
	}

	return hr;
}

HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PBYTE* ppb, _Out_ ULONG* pcb);

HRESULT PEMImport(_In_ PCWSTR lpFileName, 
				  _In_ PCWSTR szPassword, 
				  _Out_ HCERTSTORE* phStore,
				  _Out_ ULONG* pcb)
{
	*phStore = 0;
	PSTR pb;
	ULONG cb;
	HRESULT hr = ReadFromFile(lpFileName, (PBYTE*)&pb, &cb);
	if (S_OK == hr)
	{
		*pcb = cb;
		hr = PEMImport(phStore, pb, pb + cb, szPassword);
		LocalFree(pb);
	}

	return hr;
}
