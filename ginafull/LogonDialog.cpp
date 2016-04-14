// LogonDialog.cpp
//
// Gather user credentials for Logon.
//

#include "stdafx.h"
#include "LogonDialog.h"
#include "GuiHelper.h"
#include <Dsgetdc.h> 
#include <lm.h> 
#include "Commander.h"

#include "resource.h"

INT_PTR LogonDialog::DialogProc(UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
	{
        case WM_COMMAND:
			{
            switch (LOWORD(wp))
			{
                case IDOK:
                    GuiHelper::ExtractControlText(_hwnd, IDC_NAME,     &userName);
                    GuiHelper::ExtractControlText(_hwnd, IDC_PASSWORD, &password);
                    //GuiHelper::ExtractControlText(_hwnd, IDC_DOMAIN,   &domain);
					GuiHelper::ExtractComboboxText(_hwnd, IDC_DOMAINCOMBO, &domain);
                    EndDialog(_hwnd, IDOK);
                    break;
                case IDCANCEL:
                    EndDialog(_hwnd, IDCANCEL);
                    break;
            }
            return TRUE;
        }
		case WM_INITDIALOG:
		{
			HWND hCombo = GetDlgItem(_hwnd, IDC_DOMAINCOMBO);

			if (!hCombo) return FALSE;

			wchar_t buffer[256] = {0};
			DWORD size = sizeof(buffer);
			if (GetComputerName(buffer, &size))
			{
				wchar_t item[512] = {0};
				wsprintf(item, L"%s(this computer)", buffer);
				SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)item);
				Sleep(200);
			}

			// Get computer name
			LPSERVER_INFO_100 pBuf = NULL;
			LPSERVER_INFO_100 pTmpBuf;
			DWORD dwLevel = 101;
			DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
			DWORD dwEntriesRead = 0;
			DWORD dwTotalEntries = 0;
			DWORD dwTotalCount = 0;
			DWORD dwServerType = SV_TYPE_DOMAIN_ENUM; // all servers
			DWORD dwResumeHandle = 0;
			NET_API_STATUS nStatus;
			LPTSTR pszServerName = NULL;

			// try get domain names five times
			/*int index = 0;
			do
			{
				// Enum domains
				ULONG domCount = 0u; 
				PDS_DOMAIN_TRUSTS pDoms = NULL;
				DWORD result = DsEnumerateDomainTrusts( 
										NULL, 
										DS_DOMAIN_DIRECT_INBOUND |
										DS_DOMAIN_DIRECT_OUTBOUND |
										DS_DOMAIN_IN_FOREST |
										DS_DOMAIN_TREE_ROOT, 
										&pDoms, 
										&domCount 
										); 
				if (ERROR_SUCCESS == result)
				{ 
					for (ULONG i = 0; i < domCount; i++) 
					{ 
						// check domain name
						wchar_t* reverse = _wcsrev(_wcsdup(pDoms[i].DnsDomainName));
						reverse = wcsrchr(reverse, wchar_t('.'));
						if (reverse != NULL)
						{
							reverse = _wcsrev(reverse);
							size_t len = wcslen(reverse);
							reverse[len - 1] = wchar_t(0);
						}
						else
						{
							reverse = pDoms[i].DnsDomainName;
						}

						string domain = (const char*)_bstr_t(reverse);
						SendMessageA(hCombo, CB_INSERTSTRING, 0, (LPARAM)domain.c_str());
					} 
					NetApiBufferFree(pDoms); 
				}
				else
				{
					char b[256] = {0};
					sprintf(b, "error code: %d", result);
					MessageBoxA(NULL, b, "", MB_OK);
				}

				if (domCount != 0)
				{
					break;
				}

				Sleep(400);
			}while (index++ < 5);*/

			// try get domain names five times
			int index = 0;
			do
			{
				pBuf = NULL;
				dwLevel = 100;
				dwPrefMaxLen = MAX_PREFERRED_LENGTH;
				dwEntriesRead = 0;
				dwTotalEntries = 0;
				dwTotalCount = 0;
				dwServerType = SV_TYPE_DOMAIN_ENUM; // all servers
				dwResumeHandle = 0;
				nStatus;
				pszServerName = NULL;

				nStatus = NetServerEnum(pszServerName,
										dwLevel,
										(LPBYTE *) &pBuf,
										dwPrefMaxLen,
										&dwEntriesRead,
										&dwTotalEntries,
										dwServerType,
										NULL,
										&dwResumeHandle);

				if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
				{
					if ((pTmpBuf = pBuf) != NULL)
					{
						for (int i = 0; i < dwEntriesRead; i++)
						{
							SendMessage(hCombo, CB_INSERTSTRING, 0, (LPARAM)pTmpBuf->sv100_name);
							pTmpBuf++;
						}
						

						if (pBuf != NULL)
						{
							NetApiBufferFree(pBuf);
						}
						break;
					}
				}
				/*else
				{
					char b[256] = {0};
					sprintf(b, "error code: %d", nStatus);
					MessageBoxA(NULL, b, "", MB_OK);
				}*/

				Sleep(500);
			}while (index++ < 10);

			SendMessage(hCombo, CB_SETCURSEL, 0, 0);

			// Enlarge font
			HFONT font = CreateFont(50,
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

			 HWND label = GetDlgItem(_hwnd, IDC_LABELSTATIC);

			 if (font && label)
			 {
				SendMessage (label, WM_SETFONT, WPARAM(font), TRUE);
			 }

			 SetFocus(_hwnd);

			 return TRUE;
		}; break;
    }
    return FALSE;
}
