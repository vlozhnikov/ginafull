#include "StdAfx.h"
#include "PacketFrom.h"
#include "Client.h"

#include "bf.h"

PacketFrom::PacketFrom()
{
}

PacketFrom::~PacketFrom()
{
}

bool PacketFrom::FromSocket(SOCKET _socket)
{
	socket_ = _socket;
	HANDLE thread = CreateThread(NULL, 0, ThreadProc, this, 0, NULL);

	DWORD returnCode = WaitForSingleObject(thread, Client::GetWaitingTime());
	TerminateThread(thread, 0);

	CloseHandle(thread);

	return (returnCode != WAIT_TIMEOUT);
}

bool PacketFrom::GetResult(ResultReader* _reader)
{
	// Find Result attribute
	/*if (header_.encode_type == 1)
	{
		return true;
	}*/

	return _reader->Parse(data_.encoded_data);
}

DWORD WINAPI PacketFrom::ThreadProc(LPVOID _parameter)
{
	int recvSize = 0;
	PacketFrom* packet = (PacketFrom*)_parameter;

	// Read header.
	while (recvSize < sizeof(packet->header_))
	{
		recvSize += recv(packet->socket_,
			             (char*)(&packet->header_ + recvSize),
						 sizeof(packet->header_) - recvSize,
						 0);

		if (recvSize == SOCKET_ERROR)
		{
			//LDB(L"SOCKET_ERROR");
			return false;
		}
	};

	// Read data
	recvSize = 0;
	BYTE* buffer = new BYTE[packet->header_.packet_length + 1];
	memset(buffer, 0, packet->header_.packet_length + 1);

	while (recvSize < packet->header_.packet_length)
	{
		recvSize += recv(packet->socket_,
			             (char*)(buffer + recvSize),
						 packet->header_.packet_length - recvSize,
						 0);

		if (recvSize == SOCKET_ERROR)
		{
			//LDB(L"SOCKET_ERROR");
			return false;
		}
	};

	if (packet->header_.encode_type == 1)
	{
		BF_reset();
		BF_set();
		BF_decryptByte((char*)buffer, (int*)&packet->header_.packet_length);

		packet->header_.packet_length = *(buffer + strlen("ABCDEFGH"));;
		packet->data_.encoded_data = (const char*)(buffer + 
			strlen("ABCDEFGH") + sizeof(long));
	}
	else
	{
		packet->data_.encoded_data = (const char*)buffer;
	}

	delete[] buffer;

	return 0;
}