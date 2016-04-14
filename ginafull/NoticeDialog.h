// NoticeDialog.h
//
// Dialog displayed for either SAS notice or wksta locked notice
//

#pragma once

#include "WinLogonInterface.h"
#include "GinaModalDialog.h"
#include "resource.h"

class NoticeDialog : public GinaModalDialog {
public:
    NoticeDialog(IWinLogon* pWinLogon, int dialogResourceID)
        : GinaModalDialog(pWinLogon, dialogResourceID)
	{
    }

	INT_PTR DialogProc(UINT msg, WPARAM wp, LPARAM lp)
	{
		switch (msg)
		{
			case WM_INITDIALOG:
				{
					HFONT font1 = CreateFont(25,
						 0,
						 0,
						 0,
						 FW_DONTCARE,
						 FALSE,
						 FALSE,
						 FALSE,
						 ANSI_CHARSET,
						 OUT_DEFAULT_PRECIS,
						 CLIP_DEFAULT_PRECIS,
						 DEFAULT_QUALITY,
						 DEFAULT_PITCH | FF_MODERN,
						 L"Microsoft Sans Serif");

					HWND label1 = GetDlgItem(_hwnd, IDC_LABEL1STATIC);

					if (font1 && label1)
					{
						SendMessage (label1, WM_SETFONT, WPARAM(font1), TRUE);
					}

					HFONT font2 = CreateFont(40,
						 0,
						 0,
						 0,
						 FW_DONTCARE,
						 FALSE,
						 FALSE,
						 FALSE,
						 ANSI_CHARSET,
						 OUT_DEFAULT_PRECIS,
						 CLIP_DEFAULT_PRECIS,
						 DEFAULT_QUALITY,
						 DEFAULT_PITCH | FF_MODERN,
						 L"Microsoft Sans Serif");

					HWND label2 = GetDlgItem(_hwnd, IDC_LABEL2STATIC);

					if (font2 && label2)
					{
						SendMessage (label2, WM_SETFONT, WPARAM(font2), TRUE);
					}

					return TRUE;
				}; break;
		};

		return FALSE;
	}

};
