#pragma once

struct PLAIP 
{
	enum : ULONG_PTR { tag = 0x1234567890ABCDEF };
	union {
		ULONG_PTR uFakeKey;
		BCRYPT_KEY_HANDLE hFakeKey;
		PBYTE pb;
	};
	ULONG cb;
};

NTSTATUS ImportRsaKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PCWSTR pszBlobType, _In_reads_(cb) BYTE* pb, _In_ ULONG cb);

// fast (all calls in process), complex, "undocumented"
HRESULT PkcsImportPlainTextKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
							   _In_reads_(cb) BYTE* pb, 
							   _In_ ULONG cb, 
							   _Out_opt_ PULONG pcrc = 0);

HRESULT PkcsImportEncodedKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
							 _In_reads_(cb) BYTE* pb, 
							 _In_ ULONG cb, 
							 _In_ PCWSTR pszPassword, 
							 _Out_opt_ PULONG pcrc = 0);

// slow(all calls is rpc to ncryptprov.dll in lsass ), simply, "documented"
HRESULT PkcsImportKey(_Out_ NCRYPT_KEY_HANDLE* phKey, _In_reads_(cb) BYTE* pb, _In_ ULONG cb, _In_ PCWSTR pszPassword = 0);
HRESULT PkcsImportKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_reads_(cb) BYTE* pb, _In_ ULONG cb, _In_ PCWSTR pszPassword = 0);

HRESULT NKeyToBKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
				   _In_ NCRYPT_KEY_HANDLE hKey,
				   _Out_opt_ PULONG pcrc = 0);

BOOL HashKey(BCRYPT_RSAKEY_BLOB* pbrb, ULONG cb, PULONG pcrc);

HRESULT PkcsExportKey(_Out_ PBYTE *ppb, // <- base64(CRYPT_ENCRYPTED_PRIVATE_KEY_INFO)
					  _Out_ DWORD *pcb,
					  _In_ NCRYPT_KEY_HANDLE hKey,
					  _In_ PCWSTR pszPassword,
					  _In_ PCSTR pszObjId,
					  _In_ ULONG iIterations,
					  _In_ ULONG cbSalt);

HRESULT EncryptPrivateKey(_Out_ PBYTE *ppbEncoded,
						  _Out_ DWORD *pcbEncoded,
						  _In_ PBYTE pbKeyInfo, // <- CRYPT_PRIVATE_KEY_INFO
						  _In_ ULONG cbKeyInfo,
						  _In_ PCWSTR pszPassword,
						  _In_ PCSTR pszObjId,
						  _In_ ULONG iIterations,
						  _In_ ULONG cbSalt);

HRESULT DecryptPrivateKey(_Inout_ PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO pepki, _In_ PCWSTR pszPassword);





