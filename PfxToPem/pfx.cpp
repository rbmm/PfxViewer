#include "stdafx.h"

HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PBYTE* ppb, _Out_ ULONG* pcb);

HRESULT PFXImport(_In_ CRYPT_DATA_BLOB* pPFX, 
				  _In_ PCWSTR szPassword, 
				  _Out_ PCCERT_CONTEXT* ppCertContext,
				  _Out_ HCERTSTORE* phStore)
{
	HRESULT hr;
	if (HCERTSTORE hStore = HR(hr, PFXImportCertStore(pPFX, szPassword, PKCS12_NO_PERSIST_KEY|PKCS12_ALWAYS_CNG_KSP)))
	{
		PCCERT_CONTEXT pCertContext = 0;
		while (pCertContext = HR(hr, CertEnumCertificatesInStore(hStore, pCertContext)))
		{
			CERT_KEY_CONTEXT ckc = { sizeof(CERT_KEY_CONTEXT) };
			ULONG cb = sizeof(ckc);
			if (HR(hr, CertGetCertificateContextProperty(pCertContext, CERT_KEY_CONTEXT_PROP_ID, &ckc, &cb)))
			{
				if (CERT_NCRYPT_KEY_SPEC == ckc.dwKeySpec)
				{
					*ppCertContext = pCertContext;
					*phStore = hStore;
					return S_OK;
				}
			}
		}
		CertCloseStore(hStore, 0);
	}

	return hr;
}

HRESULT PFXImport(_In_ PCWSTR pszFileName, 
				  _In_ PCWSTR pszPassword, 
				  _Out_ PCCERT_CONTEXT* ppCertContext,
				  _Out_ HCERTSTORE* phStore)
{
	CRYPT_DATA_BLOB PFX;
	HRESULT hr = ReadFromFile(pszFileName, &PFX.pbData, &PFX.cbData);
	if (S_OK == hr)
	{
		hr = PFXImport(&PFX, pszPassword, ppCertContext, phStore);
		LocalFree(PFX.pbData);
	}

	return hr;
}
