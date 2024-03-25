#define SECURITY_WIN32
#include "../inc/stdafx.h"
#include <commctrl.h>
#include <WINDOWSX.H>
#include <shobjidl_core.h >
#include <Cryptuiapi.h >

_NT_BEGIN
HRESULT GetLastErrorEx(ULONG dwError = GetLastError());

template <typename T> 
T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastErrorEx();
	return t;
}

_NT_END