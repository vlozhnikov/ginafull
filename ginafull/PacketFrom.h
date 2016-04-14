#pragma once
#include "packet.h"
#include "winsock2.h"
#include "ResultReader.h"

// Encode Type is None
class PacketFrom : public Packet
{
	public:
		PacketFrom();
		~PacketFrom();

		bool FromSocket(SOCKET _socket);
		bool GetResult(ResultReader* _reader);

	private:
		static DWORD WINAPI ThreadProc(LPVOID _parameter);

		SOCKET socket_;
};
