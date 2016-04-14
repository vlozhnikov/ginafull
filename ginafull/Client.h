#pragma once
#include <string>
#include <memory>
#include "winsock2.h"
#include "PacketTo.h"

using namespace std;

class Client
{
	public:
		Client();
		virtual ~Client();

		bool Connect();
		bool Disconnect();

		Packet* SendPacket(PacketTo& _packet, bool _waiting = true);

		static string GetAddress();
		static int GetPort();
		static int GetWaitingTime();
		static int GetProtocolVersion();
		static string GetGuidType();
		static string GetSettingsPath();

	protected:
		SOCKET socket_;
		sockaddr_in clientService_; 
		bool connected_;
		int packetID_;
};
