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
	unordered_map< string, UINT >		m_pShiftTbl;
	unordered_map< string, vector< string >>	m_pHashTbl;
	VirusDB* m_pVDB;
};
