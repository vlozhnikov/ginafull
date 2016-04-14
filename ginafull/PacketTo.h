#pragma once
#include "packet.h"

#include <string>

using namespace std;

// Encode Type is None
class PacketTo : public Packet
{
	public:
		PacketTo();
		PacketTo(string _data);
		void SetID(int _id);

		~PacketTo();
};
