#pragma once

// Includes
#include "includes.h"

// Class: VirusDB
// Desc: Contains a database of Virus definitions
// Written by: James Coté
class VirusDB
{
public:
	static VirusDB* getInstance();
	~VirusDB();

	void getSignatures( vector< string >& pSigs );
	void getMinMaxOffsets( UINT& iMin, UINT& iMax );

private:
	// Singleton Implementation
	static VirusDB* m_pInstance;
	VirusDB();
	VirusDB& operator= ( const VirusDB& pCopy ) { return *this; }
	VirusDB( const VirusDB& pCopy ) {}

	void loadDB();

	struct VirusEntryStruct
	{
		string m_sSignature;
		UINT m_iOffset;
	};

	unordered_map< string, VirusEntryStruct > m_Entries;
};