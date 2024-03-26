#include "stdafx.h"

void FreeKeys(_In_ BCRYPT_KEY_HANDLE* phKeys, _In_ ULONG nKeys);

HRESULT PEMImport(_Out_ HCERTSTORE* phStore,
	_Out_ BCRYPT_KEY_HANDLE** pphKeys,
	_Out_ ULONG* pnKeys,
	_In_ PCWSTR pszFileName,
	_In_ PCWSTR pszPassword);

HRESULT GetCertForKey(_Out_ PCCERT_CONTEXT* ppCertContext,
	_In_ HCERTSTORE hStore,
	_In_ BCRYPT_KEY_HANDLE hKey);

void testcerts(HCERTSTORE hStore, BCRYPT_KEY_HANDLE* phKeys, ULONG nKeys)
{
	if (nKeys)
	{
		do
		{
			PCCERT_CONTEXT pCertContext;
			if (S_OK == GetCertForKey(&pCertContext, hStore, *phKeys++))
			{
				CertFreeCertificateContext(pCertContext);
			}
		} while (--nKeys);
	}
}

void NTAPI ep(void*)
{
	BCRYPT_KEY_HANDLE* phKeys = 0;
	ULONG nKeys = 0;
	HCERTSTORE hStore = 0;

	if (S_OK == PEMImport(&hStore, &phKeys, &nKeys, L"keypass.pem", L"keypass"))
	{
		if (hStore)
		{
			testcerts(hStore, phKeys, nKeys);
			CertCloseStore(hStore, 0);
		}

		FreeKeys(phKeys, nKeys);
	}

	ExitProcess(0);
}