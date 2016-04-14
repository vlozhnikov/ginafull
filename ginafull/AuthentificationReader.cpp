#include "StdAfx.h"
#include "AuthentificationReader.h"

#import "msxml2.dll"

AuthentificationReader::AuthentificationReader()
{
}

AuthentificationReader::~AuthentificationReader()
{
}

bool AuthentificationReader::Parse(string _data)
{
	HRESULT hr;

	MSXML2::IXMLDOMDocument2Ptr document;

	try
	{
		hr = document.CreateInstance("msxml2.domdocument");

		if (FAILED(hr))
		{
			//LDB(L"-->CoCreateInstance failed");
			return false;
		}

		document->loadXML(_bstr_t(_data.c_str()));

		MSXML2::IXMLDOMNodeListPtr nodes = document->documentElement->childNodes;
		for (int index = 0; index < nodes->length; index++)
		{
			MSXML2::IXMLDOMNodePtr node = nodes->item[index];
			if (node->baseName == _bstr_t("ParamList"))
			{
				MSXML2::IXMLDOMNodeListPtr nodesResult = node->childNodes;
				for (int index1 = 0; index1 < nodesResult->length; index1++)
				{
					MSXML2::IXMLDOMNodePtr node1 = nodesResult->item[index];
					_variant_t line = node1->attributes->getQualifiedItem(_bstr_t("id"), "")->nodeValue;
					if (_bstr_t(line) == _bstr_t("STATE"))
					{
						_variant_t line1 = node1->attributes->getQualifiedItem(_bstr_t("value"), "")->nodeValue;
						string value = string((const char*)static_cast<_bstr_t>(line1));

						if (value == "1")
						{
							return true;
						}

						break;
					}
				}
			}
		}
	}
	catch (_com_error &e)
	{
		//LDB(L"-->XML Result failed");
	}
}