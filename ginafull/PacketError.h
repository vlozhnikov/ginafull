#pragma once
#include "packet.h"

class PacketError :	public Packet
{
	public:
		PacketError();
		~PacketError();
};
