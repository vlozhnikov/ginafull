#include "StdAfx.h"
#include "Packet.h"
#include "Client.h"

Packet::Packet()
{
	memset(&header_, 0, sizeof(header_));

	header_.protocol_version = Client::GetProtocolVersion();
	header_.packet_id = 0;
	header_.encode_type = 0;
	header_.packet_length = 0;

	data_.encoded_data = "";
	buffer_ = NULL;
}

Packet::~Packet()
{
	if (buffer_ != NULL) delete[] buffer_;
}

int Packet::NextID()
{
	return ++header_.packet_id;
}

void Packet::SetData(string _data)
{
	data_.encoded_data = _data;
	header_.packet_length = _data.length();
}

BYTE* Packet::ToData()
{
	if (buffer_ != NULL) delete[] buffer_;
	buffer_ = NULL;

	buffer_ = new BYTE[sizeof(header_) + data_.encoded_data.length() + 1];
	memset(buffer_, 0, sizeof(header_) + data_.encoded_data.length() + 1);

	memcpy(buffer_, &header_, sizeof(header_));
	memcpy(buffer_ + sizeof(header_), data_.encoded_data.c_str(),
		data_.encoded_data.length());

	return buffer_;
}

string Packet::GetData()
{
	return data_.encoded_data;
}

DWORD Packet::GetLength()
{
	return header_.packet_length + sizeof(header_);
}

bool Packet::GetResult(ResultReader* _reader)
{
	return true;
}

int Packet::GetPacketID()
{
	return header_.packet_id;
}