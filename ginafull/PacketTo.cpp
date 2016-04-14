#include "StdAfx.h"
#include "PacketTo.h"

PacketTo::PacketTo()
{
	header_.encode_type = 0;
}

PacketTo::PacketTo(string _data)
{
	PacketTo();
	SetData(_data);
}

PacketTo::~PacketTo()
{
}

void PacketTo::SetID(int _id)
{
	header_.packet_id = _id;
}