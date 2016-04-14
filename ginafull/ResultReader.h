#pragma once
#include <string>

using namespace std;

class ResultReader
{
	public:
		ResultReader();
		virtual ~ResultReader();

		virtual bool Parse(string _data);
};
