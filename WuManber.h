#pragma once

#include "includes.h"
#include "VirusDB.h"

class WuManber
{
public:
	WuManber();
	~WuManber();

	void initialize( );
	void scanFile( string sFileName, vector< string >& pPotentialHits );
	void fullScan( unordered_map< string/*File Name*/, vector< string > /*Resulting Viruses*/>& pResults );

private:

	void match( ifstream* const pFP, vector< string > const * pVirusNames, vector< string >& pRetMatches );
	void scanDirectory( const string& sDirectory, unordered_map< string/*File Name*/, vector< string > /*Resulting Viruses*/>& pResults );
	
	bool isElf( const string& sFileName );
	int outputLoadBar( int iNumDots, const string& sFileName, int iMaxChars );

	unordered_map< string, UINT >		m_pShiftTbl;
	unordered_map< string, vector< string >>	m_pHashTbl;
	UINT m_iMinLen;
	VirusDB* m_pVDB;
};
