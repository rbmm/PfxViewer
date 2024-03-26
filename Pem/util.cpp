#include "stdafx.h"

HRESULT GetLastErrorEx(ULONG dwError/* = GetLastError()*/)
{
	NTSTATUS status = RtlGetLastNtStatus();
	return dwError == RtlNtStatusToDosErrorNoTeb(status) ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

NTSTATUS ReadFromFile(_In_ HANDLE hFile, _Out_ PBYTE* ppb, _Out_ ULONG* pcb)
{
	NTSTATUS status;
	FILE_STANDARD_INFORMATION fsi;
	IO_STATUS_BLOCK iosb;

	if (0 <= (status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
	{
		if (fsi.EndOfFile.QuadPart > 0x10000000)
		{
			status = STATUS_FILE_TOO_LARGE;
		}
		else
		{
			if (PBYTE pb = (PBYTE)LocalAlloc(LMEM_FIXED, fsi.EndOfFile.LowPart))
			{
				if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, pb, fsi.EndOfFile.LowPart, 0, 0)))
				{
					LocalFree(pb);
				}
				else
				{
					*ppb = pb;
					*pcb = (ULONG)iosb.Information;
				}
			}
			else
			{
				status = STATUS_NO_MEMORY;
			}
		}
	}

	return status;
}

HRESULT ReadFromFile(_In_ POBJECT_ATTRIBUTES poa, _Out_ PBYTE* ppb, _Out_ ULONG* pcb)
{
	HANDLE hFile;
	IO_STATUS_BLOCK iosb;

	NTSTATUS status = NtOpenFile(&hFile, FILE_GENERIC_READ, poa, &iosb, 
		FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE);

	if (0 <= status)
	{
		status = ReadFromFile(hFile, ppb, pcb);
		NtClose(hFile);
	}

	return status;
}

HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PBYTE* ppb, _Out_ ULONG* pcb)
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);

	if (0 <= status)
	{
		status = ReadFromFile(&oa, ppb, pcb);

		RtlFreeUnicodeString(&ObjectName);
	}

	return status ? HRESULT_FROM_NT(status) : S_OK;
}