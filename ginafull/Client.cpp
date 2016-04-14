#include "StdAfx.h"
#include "Client.h"
#include "PacketFrom.h"
#include "PacketError.h"
#include "Commander.h"
#include "PacketTo.h"

#import "msxml2.dll"

Client::Client()
{
	connected_ = false;
}

Client::~Client()
{
	Disconnect();
}

bool Client::Connect()
{
	if (connected_) return true;

	connected_ = false;
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) == NO_ERROR)
	{
		// Create a SOCKET for connecting to server
		socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (socket_ != INVALID_SOCKET)
		{
			// The sockaddr_in structure specifies the address family,
			// IP address, and port of the server to be connected to.
			clientService_.sin_family = AF_INET;
			clientService_.sin_addr.s_addr = inet_addr(Client::GetAddress().c_str());
			clientService_.sin_port = htons(Client::GetPort());

			// Connect to server.
			if (connect(socket_, (SOCKADDR*)&clientService_, sizeof(clientService_)) != SOCKET_ERROR)
			{
				connected_ = true;
			}
		}
		else
		{
			//LDB(L"-->Error at socket()");
		}
	}
	else
	{
		//LDB(L"-->Error at WSAStartup()");
	}

	return connected_;
}

bool Client::Disconnect()
{
	if (connected_)
	{
		PacketTo packetTo;
		packetTo.SetID(++packetID_);
		Commander::SendEndIdentification(packetTo, *this, NULL);

		closesocket(socket_);
		WSACleanup();
		connected_ = false;
	}

	return true;
}

Packet* Client::SendPacket(PacketTo& _packet, bool _waiting)
{
	if (connected_)
	{
		packetID_ = _packet.NextID();

		int send = 0;
		int totalSend = send;
		const char* data = (const char*)_packet.ToData();

		// Send packet to server
		while (totalSend < _packet.GetLength())
		{
			send = sendto(socket_,
				          data + totalSend,
			              _packet.GetLength() - totalSend,
						  0,
						  (SOCKADDR*)&clientService_,
			              sizeof(clientService_));
			
			totalSend += send;
			if (send == SOCKET_ERROR)
			{
				//LDB(L"SOCKET_ERROR");
				return NULL;
			}
		};

		//LDB(L"-->Finished sending");

		// Waiting for reply from server.
		PacketFrom* packetFrom = new PacketFrom();

		if (_waiting)
		{
			if (!packetFrom->FromSocket(socket_))
			{
				delete packetFrom;
				return NULL;
			}
		}

		return packetFrom;
	}

	PacketError* packetError = new PacketError();
	return packetError;
}

string Client::GetAddress()
{
	string settingsPath = Client::GetSettingsPath();

	HRESULT hr;

	MSXML2::IXMLDOMDocument2Ptr document;

	try
	{
		hr = document.CreateInstance("msxml2.domdocument");

		if (FAILED(hr))
		{
			//LDB(L"-->CoCreateInstance failed");
			return "127.0.0.1";
		}

		_variant_t varXml(settingsPath.c_str());
		document->load(varXml);

		for (int index1 = 0; index1 < document->documentElement->childNodes->length; index1++)
		{
			MSXML2::IXMLDOMNodePtr node1 = document->documentElement->childNodes->item[index1];
			if (node1->baseName == _bstr_t("Network"))
			{
				MSXML2::IXMLDOMNodeListPtr nodes = node1->childNodes;
				for (int index = 0; index < nodes->length; index++)
				{
					MSXML2::IXMLDOMNodePtr node = nodes->item[index];
					if (node->baseName == _bstr_t("Address"))
					{
						_variant_t line = node->attributes->getQualifiedItem(_bstr_t("line"), "")->nodeValue;
						return string((const char*)static_cast<_bstr_t>(line));
					}
				}
			}
		}

		return "127.0.0.1";
	}
	catch (_com_error &e)
	{
		//LDB(L"-->XML Setings failed");
	}

	return "127.0.0.1";
}

int Client::GetPort()
{
	int portValue = 2223;
	string settingsPath = Client::GetSettingsPath();

	HRESULT hr;

	MSXML2::IXMLDOMDocument2Ptr document;

	try
	{
		hr = document.CreateInstance("msxml2.domdocument");

		if (FAILED(hr))
		{
			//LDB(L"-->CoCreateInstance failed");
			return portValue;
		}

		_variant_t varXml(settingsPath.c_str());
		document->load(varXml);

		for (int index1 = 0; index1 < document->documentElement->childNodes->length; index1++)
		{
			MSXML2::IXMLDOMNodePtr node1 = document->documentElement->childNodes->item[index1];
			if (node1->baseName == _bstr_t("Network"))
			{
				MSXML2::IXMLDOMNodeListPtr nodes = node1->childNodes;
				for (int index = 0; index < nodes->length; index++)
				{
					MSXML2::IXMLDOMNodePtr node = nodes->item[index];
					if (node->baseName == _bstr_t("Address"))
					{
						_variant_t port = node->attributes->getQualifiedItem(_bstr_t("port"), "")->nodeValue;
						string portString = string((const char*)static_cast<_bstr_t>(port));
						sscanf(portString.c_str(), "%d", &portValue);
					}
				}
			}
		}

		return portValue;
	}
	catch (_com_error &e)
	{
		//LDB(L"-->XML Setings failed");
	}

	return portValue;
}

int Client::GetWaitingTime()
{
	int waitingValue = 4000;
	string settingsPath = Client::GetSettingsPath();

	HRESULT hr;

	MSXML2::IXMLDOMDocument2Ptr document;

	try
	{
		hr = document.CreateInstance("msxml2.domdocument");

		if (FAILED(hr))
		{
			//LDB(L"-->CoCreateInstance failed");
			return waitingValue;
		}

		_variant_t varXml(settingsPath.c_str());
		document->load(varXml);

		for (int index1 = 0; index1 < document->documentElement->childNodes->length; index1++)
		{
			MSXML2::IXMLDOMNodePtr node1 = document->documentElement->childNodes->item[index1];
			if (node1->baseName == _bstr_t("Network"))
			{
				MSXML2::IXMLDOMNodeListPtr nodes = node1->childNodes;
				for (int index = 0; index < nodes->length; index++)
				{
					MSXML2::IXMLDOMNodePtr node = nodes->item[index];
					if (node->baseName == _bstr_t("Options"))
					{
						_variant_t waiting = node->attributes->getQualifiedItem(_bstr_t("waiting"), "")->nodeValue;
						string waitingString = string((const char*)static_cast<_bstr_t>(waiting));
						sscanf(waitingString.c_str(), "%d", &waitingValue);
					}
				}
			}
		}

		return waitingValue;
	}
	catch (_com_error &e)
	{
		//LDB(L"-->XML Setings failed");
	}

	return waitingValue;
}

int Client::GetProtocolVersion()
{
	int protocolVersion = 6;
	string settingsPath = Client::GetSettingsPath();

	HRESULT hr;

	MSXML2::IXMLDOMDocument2Ptr document;

	try
	{
		hr = document.CreateInstance("msxml2.domdocument");

		if (FAILED(hr))
		{
			//LDB(L"-->CoCreateInstance failed");
			return protocolVersion;
		}

		_variant_t varXml(settingsPath.c_str());
		document->load(varXml);

		for (int index1 = 0; index1 < document->documentElement->childNodes->length; index1++)
		{
			MSXML2::IXMLDOMNodePtr node1 = document->documentElement->childNodes->item[index1];
			if (node1->baseName == _bstr_t("Network"))
			{
				MSXML2::IXMLDOMNodeListPtr nodes = node1->childNodes;
				for (int index = 0; index < nodes->length; index++)
				{
					MSXML2::IXMLDOMNodePtr node = nodes->item[index];
					if (node->baseName == _bstr_t("Options"))
					{
						_variant_t version = node->attributes->getQualifiedItem(_bstr_t("protocol_version"), "")->nodeValue;
						string versionString = string((const char*)static_cast<_bstr_t>(version));
						sscanf(versionString.c_str(), "%d", &protocolVersion);
					}
				}
			}
		}

		return protocolVersion;
	}
	catch (_com_error &e)
	{
		//LDB(L"-->XML Setings failed");
	}

	return protocolVersion;
}

string Client::GetGuidType()
{
	string settingsPath = Client::GetSettingsPath();

	HRESULT hr;

	MSXML2::IXMLDOMDocument2Ptr document;

	try
	{
		hr = document.CreateInstance("msxml2.domdocument");

		if (FAILED(hr))
		{
			//LDB(L"-->CoCreateInstance failed");
			return "SID";
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
					if (node->baseName == _bstr_t("Guid"))
					{
						_variant_t line = node->attributes->getQualifiedItem(_bstr_t("type"), "")->nodeValue;
						return string((const char*)static_cast<_bstr_t>(line));
					}
				}
			}
		}

		return "SID";
	}
	catch (_com_error &e)
	{
		//LDB(L"-->XML Setings failed");
	}

	return "SID";
}

string Client::GetSettingsPath()
{
	string appPath;
	TCHAR szModule[_MAX_PATH] = {0};

	if (GetSystemDirectory(szModule, _MAX_PATH) != 0)
	{
		appPath = (const char*)(_bstr_t)szModule;
		appPath += "\\";
	}

	appPath += "Seb.Gina.dll.config";
	return appPath;
}