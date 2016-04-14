#pragma once
#include "resultreader.h"

class AuthentificationReader : public ResultReader
{
	public:
		AuthentificationReader();
		virtual ~AuthentificationReader();

		bool Parse(string _data);
};
