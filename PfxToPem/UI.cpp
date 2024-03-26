#include "stdafx.h"
#include "../inc/idcres.h"
#include "resource.h"

#include "dlg.h"

#define MD5_HASH_SIZE 16

HRESULT PfxToPem(_In_ PCWSTR pszFileName, 
				 _In_ PCWSTR szPassword, 
				 _In_ PCWSTR pszNewFileName,
				 _In_opt_ PCWSTR szNewPassword = 0);

HRESULT PemToPfx(_In_ PCWSTR pszFileName, 
				 _In_ PCWSTR szPassword, 
				 _In_ PCWSTR pszNewFileName,
				 _In_ PCWSTR szNewPassword);

int ShowErrorBox(HWND hWnd, HRESULT dwError, PCWSTR lpCaption, UINT uType)
{
	int r = -1;
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		static HMODULE ghnt;
		if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return 0;
		lpSource = ghnt;
	}

	PWSTR lpText;
	if (FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
	{
		r = MessageBoxW(hWnd, lpText, lpCaption, uType);
		LocalFree(lpText);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return r;
}

class PfxDlg : public CDlgBase
{
	HICON _hi;
	WCHAR _psc;
	bool _bPem = false;
	bool _bSame = true;

	inline static UINT E_id[] = { IDC_EDIT1, IDC_EDIT2, IDC_EDIT3, IDC_EDIT4, IDC_EDIT5  };

	void OnOk(HWND hwndDlg)
	{
		PWSTR psz[_countof(E_id)] {};

		ULONG i = _countof(E_id);

		HWND hwndEdit;

		do 
		{
			psz[--i] = const_cast<PWSTR>(L"");
			if (ULONG len = GetWindowTextLengthW(hwndEdit = GetDlgItem(hwndDlg, E_id[i])))
			{
				if (len - 1 < MAXSHORT)
				{
					++len;
					GetWindowTextW(hwndEdit, psz[i] = (PWSTR)alloca(len * sizeof(WCHAR)), len);
				}
			}
		} while (i);

		if (!*psz[0] || !*psz[4])
		{
			ShowErrorBox(hwndDlg, HRESULT_FROM_NT(STATUS_OBJECT_NAME_INVALID), L"Empty File Name", MB_ICONWARNING);
			return ;
		}

		bool bSame = _bSame;
		PCWSTR caption, newpass = psz[2];

		if (!bSame)
		{
			if (wcscmp(newpass, psz[3]))
			{
				ShowErrorBox(hwndDlg, HRESULT_FROM_NT(STATUS_NOT_SAME_OBJECT), L"Passwords not match !", MB_ICONWARNING);
				return ;
			}

			if (!wcscmp(psz[1], newpass))
			{
				bSame = true;
			}
		}

		if (RtlDoesFileExists_U(psz[4]))
		{
			if (IDYES != ShowErrorBox(hwndDlg, HRESULT_FROM_NT(STATUS_OBJECT_NAME_EXISTS), L"Overwrite ?", MB_YESNO|MB_ICONWARNING))
			{
				return ;
			}
		}

		HRESULT (*convert)(_In_ PCWSTR pszFileName, _In_ PCWSTR szPassword, _In_ PCWSTR pszNewFileName, _In_ PCWSTR szNewPassword);

		if (_bPem)
		{
			caption = L"Convert PEM to PFX";
			convert = PemToPfx;
			if (bSame)
			{
				newpass = psz[1];
			}
		}
		else
		{
			caption = L"Convert PFX to PEM";
			convert = PfxToPem;
			if (bSame)
			{
				newpass = 0;
			}
		}

		ShowErrorBox(hwndDlg, convert(psz[0], psz[1], psz[4], newpass), caption, MB_ICONINFORMATION);
	}

	static void OnBrowse(HWND hwndDlg, UINT id, REFCLSID rclsid, UINT iFileType, PCWSTR pszDefaultExtension)
	{
		IFileDialog *pFileOpen;

		HRESULT hr = CoCreateInstance(rclsid, NULL, CLSCTX_ALL, IID_PPV_ARGS(&pFileOpen));

		if (SUCCEEDED(hr))
		{
			pFileOpen->SetOptions(FOS_NOVALIDATE|FOS_NOTESTFILECREATE|
				FOS_NODEREFERENCELINKS|FOS_DONTADDTORECENT|FOS_FORCESHOWHIDDEN);

			static const COMDLG_FILTERSPEC rgSpec[] =
			{ 
				{ L"PKCS#12 Files", L"*.pfx;*.p12" },
				{ L"PEM Files", L"*.pem" },
				{ L"All files", L"*" },
			};

			if (0 <= (hr = pFileOpen->SetFileTypes(_countof(rgSpec), rgSpec)) && 
				0 <= (hr = pFileOpen->SetFileTypeIndex(iFileType)) && 
				0 <= (hr = pFileOpen->SetDefaultExtension(pszDefaultExtension)) &&
				0 <= (hr = pFileOpen->Show(hwndDlg)))
			{
				IShellItem *pItem;
				hr = pFileOpen->GetResult(&pItem);

				if (SUCCEEDED(hr))
				{
					PWSTR pszFilePath;
					hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);

					if (SUCCEEDED(hr))
					{
						SetDlgItemTextW(hwndDlg, id, pszFilePath);
						CoTaskMemFree(pszFilePath);
					}
					pItem->Release();
				}
			}
			pFileOpen->Release();
		}
	}

	void OnInitDialog(HWND hwndDlg)
	{
		if (HICON hi = LoadIconW((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(1)))
		{
			_hi = hi;
			SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)hi);
		}

		static const PCWSTR ss[] = {
			L"Specify the file you want to convert.",
			L"Type the password for the private key.",
			L"Enter new password",
			L"Confirm password",
			L"Specify the output file.",
		};

		ULONG n = _countof(E_id);
		do 
		{
			--n;
			SendDlgItemMessage(hwndDlg, E_id[n], EM_SETCUEBANNER, FALSE, (LPARAM)ss[n]);
		} while (n);

		_psc = (WCHAR)SendDlgItemMessage(hwndDlg, IDC_EDIT2, EM_GETPASSWORDCHAR, 0, 0);

		SendDlgItemMessage(hwndDlg, IDC_CHECK3, BM_SETCHECK, BST_CHECKED, 0);
		SendDlgItemMessage(hwndDlg, IDC_RADIO1, BM_SETCHECK, BST_CHECKED, 0);

		SetFocus(GetDlgItem(hwndDlg, IDC_BUTTON1));
	}

	void TooglePasswordChar(HWND hwndDlg, HWND hwndCheck, UINT id, UINT id2 = 0)
	{
		WCHAR c = SendMessageW(hwndCheck, BM_GETCHECK, 0, 0) == BST_CHECKED ? 0 : _psc;

		do 
		{
			if (hwndCheck = GetDlgItem(hwndDlg, id))
			{
				SendMessageW(hwndCheck, EM_SETPASSWORDCHAR, c, 0);
				InvalidateRect(hwndCheck, 0, FALSE);
			}

		} while ((id != id2) && (id = id2));
	}

	void Enable(HWND hwndDlg, BOOL bEnable)
	{
		_bSame = !bEnable;
		static const UINT id[] = { IDC_STATIC1, IDC_STATIC2, IDC_EDIT3, IDC_EDIT4, IDC_CHECK2 };
		ULONG n = _countof(id);
		do 
		{
			EnableWindow(GetDlgItem(hwndDlg, id[--n]), bEnable);
		} while (n);
	}

	virtual INT_PTR DlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		switch (uMsg)
		{
		case WM_NCDESTROY:
			OnNcDestroy();
			break;

		case WM_COMMAND:
			switch (wParam)
			{
			case IDCANCEL:
				EndDialog(hwndDlg, 0);
				break;

			case MAKEWPARAM(IDC_BUTTON1, BN_CLICKED):
				OnBrowse(hwndDlg, IDC_EDIT1, __uuidof(FileOpenDialog), _bPem + 1, _bPem ? L".pem" : L".pfx");
				break;
			
			case MAKEWPARAM(IDC_BUTTON2, BN_CLICKED):
				OnBrowse(hwndDlg, IDC_EDIT5, __uuidof(FileSaveDialog), 2 - _bPem, _bPem ? L".pfx" : L".pem");
				break;

			case MAKEWPARAM(IDOK, BN_CLICKED):
				OnOk(hwndDlg);
				break;

			case MAKEWPARAM(IDC_CHECK1, BN_CLICKED):
				TooglePasswordChar(hwndDlg, (HWND)lParam, IDC_EDIT2);
				break;

			case MAKEWPARAM(IDC_CHECK2, BN_CLICKED):
				TooglePasswordChar(hwndDlg, (HWND)lParam, IDC_EDIT3, IDC_EDIT4);
				break;

			case MAKEWPARAM(IDC_CHECK3, BN_CLICKED):
				Enable(hwndDlg, SendMessageW((HWND)lParam, BM_GETCHECK, 0, 0) != BST_CHECKED);
				break;

			case MAKEWPARAM(IDC_RADIO1, BN_CLICKED):
				_bPem = FALSE;
				SetWindowTextW(hwndDlg, L"Convert PFX to PEM");
				break;

			case MAKEWPARAM(IDC_RADIO2, BN_CLICKED):
				_bPem = TRUE;
				SetWindowTextW(hwndDlg, L"Convert PEM to PFX");
				break;
			}
			return 0;

		case WM_INITDIALOG:
			OnInitDialog(hwndDlg);
			break;

		case WM_DESTROY:
			if (HICON hi = _hi) DestroyIcon(hi);
			break;

		case WM_CTLCOLOREDIT:
			SetBkColor((HDC)wParam, GetSysColor(COLOR_WINDOW));
			SetBkMode((HDC)wParam, TRANSPARENT);
			[[fallthrough]];
		case WM_CTLCOLORDLG:
			return (INT_PTR)GetSysColorBrush(COLOR_WINDOW);

		case WM_CTLCOLORSTATIC:
			SetTextColor((HDC)wParam, (INT_PTR)GetSysColor(COLOR_WINDOWTEXT));
			SetBkMode((HDC)wParam, TRANSPARENT);
			return (INT_PTR)GetSysColorBrush(COLOR_WINDOW);

		case WM_PAINT:
			PAINTSTRUCT ps;
			if (BeginPaint(hwndDlg, &ps))
			{
				RECT rc;
				GetWindowRect(GetDlgItem(hwndDlg, IDOK), &rc);
				MapWindowRect(0, hwndDlg, &rc);
				
				GetClientRect(hwndDlg, &ps.rcPaint);
				ps.rcPaint.top = rc.top - (ps.rcPaint.bottom - rc.bottom);
				FillRect(ps.hdc, &ps.rcPaint, GetSysColorBrush(COLOR_MENU));
				EndPaint(hwndDlg, &ps);
			}
			return TRUE;
		}

		return 0;
	}
};

void WINAPI ep(void*)
{
	if (0 <= CoInitializeEx(0, COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE))
	{
		PfxDlg dlg;
		dlg.DoModal(MAKEINTRESOURCEW(IDD_DIALOG1));

		CoUninitialize();
	}

	ExitProcess(0);
}
