#pragma once

class __declspec(novtable) CDlgBase
{
	LONG _M_dwRefCount = 1;
	LONG _M_dwCallCount = 1 << 31;

	virtual INT_PTR DlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) = 0;

	INT_PTR WrapDlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

	static INT_PTR CALLBACK StaticDlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

	virtual void OnFinalMessage()
	{
		Release();
	}

protected:

	virtual ~CDlgBase() = default;

	void OnNcDestroy()
	{
		_bittestandreset(&_M_dwCallCount, 31);
	}

public:

	void AddRef()
	{
		InterlockedIncrementNoFence(&_M_dwRefCount);
	}

	void Release()
	{
		if (!InterlockedDecrement(&_M_dwRefCount))
		{
			delete this;
		}
	}

	INT_PTR DoModal(_In_ PCWSTR lpTemplateName, _In_opt_ HWND hWndParent = 0, _In_opt_ HINSTANCE hInstance = (HINSTANCE)&__ImageBase)
	{
		return DialogBoxParamW(hInstance, lpTemplateName, hWndParent, StaticDlgProc, (LPARAM)this);
	}

	HWND Create(_In_ PCWSTR lpTemplateName, _In_opt_ HWND hWndParent = 0, _In_opt_ HINSTANCE hInstance = (HINSTANCE)&__ImageBase)
	{
		return CreateDialogParamW(hInstance, lpTemplateName, hWndParent, StaticDlgProc, (LPARAM)this);
	}
};
