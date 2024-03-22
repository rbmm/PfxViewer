#include "stdafx.h"

_NT_BEGIN

HRESULT GetLastErrorEx(ULONG dwError = GetLastError())
{
	NTSTATUS status = RtlGetLastNtStatus();
	return dwError == RtlNtStatusToDosErrorNoTeb(status) ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

template <typename T> 
T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastErrorEx();
	return t;
}

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

HRESULT PFXImport(_In_ PCWSTR lpFileName, 
				  _In_ PCWSTR szPassword, 
				  _Out_ PCCERT_CONTEXT* ppCertContext,
				  _Out_ HCERTSTORE* phStore)
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
			CRYPT_DATA_BLOB PFX;
			if (PFX.pbData = new UCHAR [PFX.cbData = fsi.EndOfFile.LowPart])
			{
				if (0 <= (status = NtReadFile(hFile, 0, 0, 0, &iosb, PFX.pbData, PFX.cbData, 0, 0)))
				{
					f = 0;
					status = PFXImport(&PFX, szPassword, ppCertContext, phStore);
				}

				delete [] PFX.pbData;
			}
		}
	}

	NtClose(hFile);

	return status ? status | f : S_OK;
}

_NT_END