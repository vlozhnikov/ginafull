#pragma once
#include "PacketTo.h"
#include "Client.h"
#include <string>
#include "comutil.h"

using namespace std;

class Commander
{
	public:
		static bool SendSetProtocolCommand(PacketTo& _packetTo, Client& _client, PSID _sid);
		static bool SendIdentityCommand(PacketTo& _packetTo, Client& _client, PSID _sid);
		static bool SendStartIdentificationCommand(PacketTo& _packetTo, Client& _client, PSID _sid);
		static bool SendPersonAuthentificationCommand(PacketTo& _packetTo, Client& _client, PSID _sid, string _userName);
		static bool SendTerminalPersonAuthorizationCommand(PacketTo& _packetTo, Client& _client, PSID _sid, string _userName);
		static bool SendEndIdentification(PacketTo& _packetTo, Client& _client, PSID _sid);

		static bool IsServerConnected1();
		static bool IsServerConnected2();

	private:
		Commander();
		~Commander();

		static string GetIPAddress();
		static _bstr_t GetUserID(PSID _sid, string _userName);
		//static string GetUserGuid(PSID _sid);
		static bool IsCtrlAltDelCommand();
		static bool IsAuthentificationCommand();
};
