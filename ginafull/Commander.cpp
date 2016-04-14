#include "StdAfx.h"
#include "Commander.h"
#include "ResultReader.h"
#include "AuthentificationReader.h"
#include "Sddl.h"
#include "Ntdsapi.h"
#include "Gina.h"

#define SECURITY_WIN32
#include "Security.h"

#import "msxml2.dll"

Commander::Commander()
{
}

Commander::~Commander()
{
}

bool Commander::SendSetProtocolCommand(PacketTo& _packetTo, Client& _client, PSID _sid)
{
	if (!IsCtrlAltDelCommand()) return true;

	char set_protocolCommand[1024] = {0};
	sprintf(set_protocolCommand,
		"<Command name=\"SET_PROTOCOL\" id=\"%d\"><RequireAck value=\"0\" /><CommandType value=\"SERVICE\" /><ParamList><Param id=\"VERSION\" value=\"%d\" /><Param id=\"RESULT\" value=\"\" /></ParamList></Command>",
		_packetTo.GetPacketID(), Client::GetProtocolVersion());

	_packetTo.SetData(set_protocolCommand);
	Packet* packetFrom = _client.SendPacket(_packetTo);
	if (packetFrom != NULL)
	{
		ResultReader resultReader;
		bool result = packetFrom->GetResult(&resultReader);
		delete packetFrom;

		return result;
	}
	else
	{
		if (Commander::IsServerConnected1())
		{
			if (MessageBox(NULL,
				L"LOGIN is not secure. Camera was not moved. Do you want continue to logon anyway?",
				L"Security",
				MB_ICONQUESTION | MB_YESNO) == IDYES)
			{
				return true;
			}
		}
	}

	return false;
}

bool Commander::SendIdentityCommand(PacketTo& _packetTo, Client& _client, PSID _sid)
{
	if (!IsCtrlAltDelCommand()) return true;

	char identityCommand[1024] = {0};
	sprintf(identityCommand, "<Command name=\"IDENTITY\" id=\"%d\"><CommandType value=\"SERVICE\" /><ParamList><Param id=\"PROGRAM\" value=\"PA\" /><Param id=\"IP\" value=\"%s\" /><Param id=\"VERSION\" value=\"1.0.2026.17160\" /></ParamList></Command>",
		_packetTo.GetPacketID(), GetIPAddress().c_str());
	_packetTo.SetData(identityCommand);

	_packetTo.SetData(identityCommand);
	Packet* packetFrom = _client.SendPacket(_packetTo);
	if (packetFrom != NULL)
	{
		ResultReader resultReader;
		bool result = packetFrom->GetResult(&resultReader);
		delete packetFrom;

		return result;
	}
	else
	{
		if (Commander::IsServerConnected1())
		{
			if (MessageBox(NULL,
				L"LOGIN is not secure. Camera was not moved. Do you want continue to logon anyway?",
				L"Security",
				MB_ICONQUESTION | MB_YESNO) == IDYES)
			{
				return true;
			}
		}
	}

	return false;
}

bool Commander::SendStartIdentificationCommand(PacketTo& _packetTo, Client& _client, PSID _sid)
{
	if (!IsCtrlAltDelCommand()) return true;

	SYSTEMTIME time = {0};
	GetSystemTime(&time);

	char buffer[1024] = {0};
	sprintf(buffer, "<Command name=\"EVENT\" id=\"%d\"><RequireAck value=\"1\" /><CommandType value=\"COMMON\"/><EventCode value=\"START_IDENTIFICATION\"/><EventType value=\"INFO\"/><ItemGroup value=\"TERMINAL\"/><ParamList><Param id=\"TIMESTAMP\" value=\"%d-%d-%d %d:%d:%d.%d\"/><Param id=\"PROGRAM\" value=\"LOGIN_CONTROL_CLIENT\"/><Param id=\"IP\" value=\"%s\"/></ParamList></Command>",
			_packetTo.GetPacketID(),
			time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
			GetIPAddress().c_str());

	_packetTo.SetData(buffer);
	Packet* packetFrom = _client.SendPacket(_packetTo);
	if (packetFrom != NULL)
	{
		delete packetFrom;
		return true;
	}
	else
	{
		if (Commander::IsServerConnected1())
		{
			if (MessageBox(NULL,
				L"LOGIN is not secure. Camera was not moved. Do you want continue to logon anyway?",
				L"Security",
				MB_ICONQUESTION | MB_YESNO) == IDYES)
			{
				return true;
			}
		}
	}

	return false;
}

bool Commander::SendPersonAuthentificationCommand(PacketTo& _packetTo, Client& _client, PSID _sid, string _userName)
{
	char identityCommand[1024] = {0};
	SYSTEMTIME time = {0};
	GetSystemTime(&time);

	sprintf(identityCommand, "<Command name=\"EVENT\" id=\"%d\"><CommandType value=\"COMMON\"/><EventCode value=\"PERSON_AUTHENTIFICATION\"/><EventType value=\"INFO\"/><ItemGroup value=\"TERMINAL\"/><ParamList><Param id=\"ITEM_ID\" value=\"%s\"/><Param id=\"STATE\" value=\"0\"/><Param id=\"TIMESTAMP\" value=\"%d-%d-%d %d:%d:%d.%d\"/><Param id=\"PROGRAM\" value=\"LOGIN_CONTROL_CLIENT\"/><Param id=\"IP\" value=\"%s\"/></ParamList></Command>",
			_packetTo.GetPacketID(),
			(const char*)GetUserID(_sid, _userName),
			time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
			GetIPAddress().c_str());

	_packetTo.SetData(identityCommand);
	_client.SendPacket(_packetTo, false);

	return true;
}

bool Commander::SendTerminalPersonAuthorizationCommand(PacketTo& _packetTo, Client& _client, PSID _sid, string _userName)
{
	if (!IsAuthentificationCommand()) return true;

	char identityCommand[1024] = {0};
	SYSTEMTIME time = {0};
	GetSystemTime(&time);

	sprintf(identityCommand, "<Command name=\"ACTION\" id=\"%d\"><CommandType value=\"COMMON\"/><ActionCode value=\"TERMINAL_PERSON_AUTHORIZATION\"/><ParamList><Param id=\"ITEM_ID\" value=\"%s\"/><Param id=\"TIMESTAMP\" value=\"%d-%d-%d %d:%d:%d.%d\"/><Param id=\"PROGRAM\" value=\"LOGIN_CONTROL_CLIENT\"/><Param id=\"IP\" value=\"%s\"/></ParamList></Command>",
			_packetTo.GetPacketID(),
			(const char*)GetUserID(_sid, _userName),
			time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
			GetIPAddress().c_str());

	_packetTo.SetData(identityCommand);
	Packet* packetFrom = _client.SendPacket(_packetTo);
	if (packetFrom != NULL)
	{
		ResultReader resultReader;
		bool result = packetFrom->GetResult(&resultReader);

		delete packetFrom;
		return result;
	}
	else
	{
		if (Commander::IsServerConnected2())
		{
			if (MessageBox(NULL,
				L"LOGIN is not secure. If you will Login anyway a ALARM will be send. Do you want to continue?",
				L"Security",
				MB_ICONQUESTION | MB_YESNO) == IDYES)
			{
				return true;
			}
		}
	}

	return false;
}

bool Commander::SendEndIdentification(PacketTo& _packetTo, Client& _client, PSID _sid)
{
	char identityCommand[1024] = {0};
	SYSTEMTIME time = {0};
	GetSystemTime(&time);

	sprintf(identityCommand, "<Command name=\"EVENT\" id=\"%d\"><RequireAck value=\"0\" /><CommandType value=\"COMMON\" /><EventCode value=\"END_IDENTIFICATION\" /><EventType value=\"INFO\" /><ItemGroup value=\"TERMINAL\" /><ParamList><Param id=\"TIMESTAMP\" value=\"%d-%d-%d %d:%d:%d.%d\" /><Param id=\"PROGRAM\" value=\"LOGIN_CONTROL_CLIENT\"/><Param id=\"IP\" value=\"%s\" /></ParamList></Command>",
			_packetTo.GetPacketID(),
			time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
			GetIPAddress().c_str());

	_packetTo.SetData(identityCommand);
	_client.SendPacket(_packetTo, false);

	return true;
}

string Commander::GetIPAddress()
{
	// Get cient ip address dynamically
	// Get local host name
	char hostName[128] = {0};
	if(::gethostname(hostName, sizeof(hostName)))
	{
		return "127.0.0.1";
	}

	// Get local IP addresses
	struct sockaddr_in socketAddress;
	struct hostent *host = NULL;

	host = ::gethostbyname(hostName);
	if(!host)
	{
		return "127.0.0.1";
	}

	char IPAddresses[10][16] = {0}; // maximum of ten IP addresses
	for(int iCnt = 0; ((host->h_addr_list[iCnt]) && (iCnt < 10)); ++iCnt)
	{
		memcpy(&socketAddress.sin_addr, host->h_addr_list[iCnt], host->h_length);
		strcpy(IPAddresses[iCnt], inet_ntoa(socketAddress.sin_addr));
		break;
	}

	string address = IPAddresses[0];
	return address;
}

_bstr_t Commander::GetUserID(PSID _sid, string _userName)
{
	string type = Client::GetGuidType();
	if (type == "SID")
	{
		if (_sid != NULL)
		{
			LPTSTR p;
			ConvertSidToStringSid(_sid, &p);
			_bstr_t sid = _bstr_t(p);
			LocalFree(p);

			return sid;
		}
	}
	/*else */if (type == "UserName")
	{
		return _bstr_t(_userName.c_str());
	}

	return _bstr_t(L"");
}

/*string Commander::GetUserGuid(PSID _sid)
{
	_bstr_t sid = GetUserID(_sid, "");
	HANDLE hDS;
    DWORD dwRet = DsBind(NULL, NULL, &hDS);
	switch (dwRet)
	{
		case ERROR_INVALID_PARAMETER:
		{
			MessageBox(NULL, L"ERROR_INVALID_PARAMETER", L"", MB_OK);
			return "";
		}; break;
		case ERROR_NO_SUCH_DOMAIN:
		{
			MessageBox(NULL, L"ERROR_NO_SUCH_DOMAIN", L"", MB_OK);
			return "";
		}; break;
		case ERROR_INVALID_DOMAINNAME:
		{
			MessageBox(NULL, L"ERROR_INVALID_DOMAINNAME", L"", MB_OK);
			return "";
		}; break;
		case ERROR_NOT_ENOUGH_MEMORY:
		{
			MessageBox(NULL, L"ERROR_NOT_ENOUGH_MEMORY", L"", MB_OK);
			return "";
		}; break;
	};

	LPCTSTR pszSid = (LPCTSTR)sid;

	PDS_NAME_RESULT pRes;
	dwRet = DsCrackNames(hDS,
		DS_NAME_NO_FLAGS,
		DS_SID_OR_SID_HISTORY_NAME,
		DS_UNIQUE_ID_NAME,
		1,
		&pszSid,
		&pRes);
	DsUnBind(&hDS);
	if (dwRet != ERROR_SUCCESS)
	{
		MessageBox(NULL, L"DsCrackNames failed", L"", MB_OK);
		return "";
	}

	if (pRes->rItems[0].status != DS_NAME_NO_ERROR)
	{
		MessageBox(NULL, L"pRes->rItems[0].status failed", L"", MB_OK);
		return "";
	}
	
	string guid = string((const char*)_bstr_t(pRes->rItems[0].pName));
	MessageBox(NULL, L"guid", L"", MB_OK);

	return guid;
}*/

bool Commander::IsCtrlAltDelCommand()
{
	string settingsPath = Client::GetSettingsPath();

	int commandValue = 1;

	HRESULT hr;

	MSXML2::IXMLDOMDocument2Ptr document;

	try
	{
		hr = document.CreateInstance("msxml2.domdocument");

		if (FAILED(hr))
		{
			LDB(L"-->CoCreateInstance failed");
			return true;
		}

		_variant_t varXml(settingsPath.c_str());
		document->load(varXml);

		for (int index1 = 0; index1 < document->documentElement->childNodes->length; index1++)
		{
			MSXML2::IXMLDOMNodePtr node1 = document->documentElement->childNodes->item[index1];
			if (node1->baseName == _bstr_t("Settings"))
			{
				MSXML2::IXMLDOMNodeListPtr nodes = node1->childNodes;
				for (int index = 0; index < nodes->length; index++)
				{
					MSXML2::IXMLDOMNodePtr node = nodes->item[index];
					if (node->baseName == _bstr_t("Command"))
					{
						_variant_t line = node->attributes->getQualifiedItem(_bstr_t("SendCtrlAltDel"), "")->nodeValue;
						string command =  string((const char*)static_cast<_bstr_t>(line));
						sscanf(command.c_str(), "%d", &commandValue);
					}
				}
			}
		}
	}
	catch (_com_error &e)
	{
		LDB(L"-->XML Setings failed");
	}

	return commandValue == 1;
}

bool Commander::IsAuthentificationCommand()
{
	string settingsPath = Client::GetSettingsPath();

	int commandValue = 1;

	HRESULT hr;

	MSXML2::IXMLDOMDocument2Ptr document;

	try
	{
		hr = document.CreateInstance("msxml2.domdocument");

		if (FAILED(hr))
		{
			LDB(L"-->CoCreateInstance failed");
			return true;
		}

		_variant_t varXml(settingsPath.c_str());
		document->load(varXml);

		for (int index1 = 0; index1 < document->documentElement->childNodes->length; index1++)
		{
			MSXML2::IXMLDOMNodePtr node1 = document->documentElement->childNodes->item[index1];
			if (node1->baseName == _bstr_t("Settings"))
			{
				MSXML2::IXMLDOMNodeListPtr nodes = node1->childNodes;
				for (int index = 0; index < nodes->length; index++)
				{
					MSXML2::IXMLDOMNodePtr node = nodes->item[index];
					if (node->baseName == _bstr_t("Command"))
					{
						_variant_t line = node->attributes->getQualifiedItem(_bstr_t("SendAuthentification"), "")->nodeValue;
						string command =  string((const char*)static_cast<_bstr_t>(line));
						sscanf(command.c_str(), "%d", &commandValue);
					}
				}
			}
		}
	}
	catch (_com_error &e)
	{
		LDB(L"-->XML Setings failed");
	}

	return commandValue == 1;
}

bool Commander::IsServerConnected1()
{
	string settingsPath = Client::GetSettingsPath();

	int commandValue = 1;

	HRESULT hr;

	MSXML2::IXMLDOMDocument2Ptr document;

	try
	{
		hr = document.CreateInstance("msxml2.domdocument");

		if (FAILED(hr))
		{
			LDB(L"-->CoCreateInstance failed");
			return true;
		}

		_variant_t varXml(settingsPath.c_str());
		document->load(varXml);

		for (int index1 = 0; index1 < document->documentElement->childNodes->length; index1++)
		{
			MSXML2::IXMLDOMNodePtr node1 = document->documentElement->childNodes->item[index1];
			if (node1->baseName == _bstr_t("Settings"))
			{
				MSXML2::IXMLDOMNodeListPtr nodes = node1->childNodes;
				for (int index = 0; index < nodes->length; index++)
				{
					MSXML2::IXMLDOMNodePtr node = nodes->item[index];
					if (node->baseName == _bstr_t("Command"))
					{
						_variant_t line = node->attributes->getQualifiedItem(_bstr_t("CtrlAltDelAskUser"), "")->nodeValue;
						string command =  string((const char*)static_cast<_bstr_t>(line));
						sscanf(command.c_str(), "%d", &commandValue);
					}
				}
			}
		}
	}
	catch (_com_error &e)
	{
		LDB(L"-->XML Setings failed");
	}

	return commandValue == 1;
}

bool Commander::IsServerConnected2()
{
	string settingsPath = Client::GetSettingsPath();

	int commandValue = 1;

	HRESULT hr;

	MSXML2::IXMLDOMDocument2Ptr document;

	try
	{
		hr = document.CreateInstance("msxml2.domdocument");

		if (FAILED(hr))
		{
			LDB(L"-->CoCreateInstance failed");
			return true;
		}

		_variant_t varXml(settingsPath.c_str());
		document->load(varXml);

		for (int index1 = 0; index1 < document->documentElement->childNodes->length; index1++)
		{
			MSXML2::IXMLDOMNodePtr node1 = document->documentElement->childNodes->item[index1];
			if (node1->baseName == _bstr_t("Settings"))
			{
				MSXML2::IXMLDOMNodeListPtr nodes = node1->childNodes;
				for (int index = 0; index < nodes->length; index++)
				{
					MSXML2::IXMLDOMNodePtr node = nodes->item[index];
					if (node->baseName == _bstr_t("Command"))
					{
						_variant_t line = node->attributes->getQualifiedItem(_bstr_t("AuthentificationAskUser"), "")->nodeValue;
						string command =  string((const char*)static_cast<_bstr_t>(line));
						sscanf(command.c_str(), "%d", &commandValue);
					}
				}
			}
		}
	}
	catch (_com_error &e)
	{
		LDB(L"-->XML Setings failed");
	}

	return commandValue == 1;
}