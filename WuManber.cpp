#include "WuManber.h"

WuManber::WuManber()
{
	m_pVDB = VirusDB::getInstance();
}
WuManber::~WuManber()
{
	m_pVDB = NULL;
}

void WuManber::initialize( )
{
	// Local Variables
	UINT bMinLen = -1, q_xy;
	vector< string >::const_iterator iter;
	vector< string > pMinLngthSubstrs;
	vector< string > pTwoByters;
	vector< string > pSignatures;

	// Get list of Signatures from Virus Database
	m_pVDB->getSignatures( pSignatures );

	// Calculate MINLEN (Minimum number of adjacent, non-wildard bytes in any signature)
	for ( iter = pSignatures.begin();
		 iter != pSignatures.end();
		 ++iter )
		if ( iter->size() < bMinLen )
			bMinLen = iter->size();

	// Create a list of substrings of minimum length
	for ( iter = pSignatures.begin();
		 iter != pSignatures.end();
		 ++iter )
		pMinLngthSubstrs.push_back( iter->substr( 0, bMinLen ) );

	// split each minlength string into all possible combinations of two-byte identifiers
	for ( iter = pMinLngthSubstrs.begin();
		 iter != pMinLngthSubstrs.end();
		 ++iter )
		for ( UINT i = 0; i <= (bMinLen - 2); ++i )
			m_pShiftTbl.insert( {iter->substr( i, 2 ), bMinLen - 1} );	// Initialize a new Shift Table value for each two-byte identifier

	// Evaluate the Shift Table and populate the Hash Table
	for ( unordered_map< string, UINT >::iterator shiftIter = m_pShiftTbl.begin();
		  shiftIter != m_pShiftTbl.end();
		  ++shiftIter )
	{	// For each entry in the shift table calculate the nearest offset to a potential match
		for ( UINT i = 0; i < pMinLngthSubstrs.size(); ++i  )
		{
			// Calculate the q_xy (MINLEN - the distance from two-byte identifier to end of signature substring)
			q_xy = bMinLen - (pMinLngthSubstrs[i].find( shiftIter->first ) + 2);
			shiftIter->second = (q_xy < shiftIter->second ? q_xy : shiftIter->second);	// Keep the minimum
			if ( !q_xy )										
				m_pHashTbl[ shiftIter->first ].push_back( pSignatures[i] );	// If q_xy == 0, store full string in the hash table as a potential hit.
		}
	}


#ifdef DEBUG
	cout << "SHIFT Table:\n";
	for ( unordered_map< string, UINT >::iterator shiftIter = m_pShiftTbl.begin();
		 shiftIter != m_pShiftTbl.end();
		 ++shiftIter )
		cout << shiftIter->first << "\t" << shiftIter->second << endl;

	cout << "HASH Table:\n";
	for ( unordered_map< string, vector< string > >::iterator HashIter = m_pHashTbl.begin();
		  HashIter != m_pHashTbl.end();
		  ++HashIter )
	{
		cout << HashIter->first << "\t";
		for ( vector< string >::iterator strIter = HashIter->second.begin();
			 strIter != HashIter->second.end();
			 ++strIter )
			cout << (*strIter) << (strIter + 1 == HashIter->second.end() ? "\n" : ",");
	}
#endif
}
