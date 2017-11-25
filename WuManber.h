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

private:

	void match( ifstream* const pFP, vector< string > const * pVirusNames, vector< string >& pRetMatches );

	unordered_map< string, UINT >		m_pShiftTbl;
	unordered_map< string, vector< string >>	m_pHashTb;
	UINT m_iMinLen;
	VirusDB* m_pVDB;
};
