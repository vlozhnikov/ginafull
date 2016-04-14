#pragma once
#pragma pack(1)
#include "ResultReader.h"
#include <string>

using namespace std;

class Packet
{
	public:
		virtual ~Packet();
		int NextID();

		virtual void SetData(string _data);
		virtual BYTE* ToData();
		virtual string GetData();
		virtual DWORD GetLength();
		virtual bool GetResult(ResultReader* _reader);
		virtual int GetPacketID();

	protected:
		Packet();

		struct packet_header
		{
			BYTE protocol_version;
			DWORD packet_id;
			BYTE encode_type; //0 – none ,1 – Blowfish ,…
			DWORD packet_length;
		} header_;

		struct packet_enc_data
		{
			string encoded_data;
		} data_;

		BYTE* buffer_;
};
