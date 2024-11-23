#pragma once

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




