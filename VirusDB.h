#pragma once

// Includes
#include <unordered_map>
#include <string>

// namespaces
using namespace std;

// Class: VirusDB
// Desc: Contains a database of Virus definitions
// Written by: James Coté
class VirusDB
{
public:
	VirusDB();
	~VirusDB();

private:

	void loadDB();

	struct VirusEntryStruct
	{
		string m_sSignature;
		unsigned int m_iOffset;
	};

	unordered_map< string, VirusEntryStruct > m_Entries;
};