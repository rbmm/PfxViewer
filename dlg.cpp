#include "stdafx.h"

_NT_BEGIN

#include "dlg.h"

INT_PTR CDlgBase::WrapDlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	_M_dwCallCount++;
	INT_PTR r = DlgProc(hwnd, uMsg, wParam, lParam);
	if (!--_M_dwCallCount)
	{
		OnFinalMessage();
	}
	return r;
}

INT_PTR CALLBACK CDlgBase::StaticDlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	LONG_PTR This = GetWindowLongPtrW(hwnd, DWLP_USER);

	if (!This)
	{
		switch (uMsg)
		{
		case WM_INITDIALOG:
			if (This = lParam)
			{
				reinterpret_cast<CDlgBase*>(This)->AddRef();
				break;
			}
		default:
			return 0;
		}

		SetWindowLongPtrW(hwnd, DWLP_USER, This);
	}

	return reinterpret_cast<CDlgBase*>(This)->WrapDlgProc(hwnd, uMsg, wParam, lParam);
}

_NT_END
