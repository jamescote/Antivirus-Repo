#include "WuManber.h"

// Constants
const string sDirectories[] = { "/usr/bin", "/bin", "/sbin" };
const UBYTE sELF[] = { "\x7f\x45\x4c\x46" };

// Defines
#define NUM_ELF_BYTES 4
#define DEFAULT_NUM_LOAD_CHARS 13
#define NUM_ELIPSIS 4

WuManber::WuManber()
{
	m_pVDB = VirusDB::getInstance();
	m_iMinLen = -1;
}
WuManber::~WuManber()
{
	m_pVDB = NULL;
}

void WuManber::initialize( )
{
	// Local Variables
	UINT q_xy;
	unordered_map< string, VirusEntryStruct >::const_iterator iter;
	vector< string > pKeys;
	vector< string > pMinLngthSubstrs;
	vector< string > pTwoByters;
	const unordered_map< string, VirusEntryStruct >* pDB = m_pVDB->getDBPtr();

	// Calculate MINLEN (Minimum number of adjacent, non-wildard bytes in any signature)
	for ( iter = pDB->begin();
		 iter != pDB->end();
		 ++iter )
	{
		if ( iter->second.m_sSignature.length() < m_iMinLen )
			m_iMinLen = iter->second.m_sSignature.length();
		pKeys.push_back( iter->first );
	}

	// Create a list of substrings of minimum length
	for ( iter = pDB->begin();
		  iter != pDB->end();
		 ++iter )
		pMinLngthSubstrs.push_back( iter->second.m_sSignature.substr( 0, m_iMinLen ) );
	
	// split each minlength string into all possible combinations of two-byte identifiers
	for ( vector< string >::iterator strIter = pMinLngthSubstrs.begin();
		  strIter != pMinLngthSubstrs.end();
		 ++strIter )
		for ( UINT i = 0; i <= (m_iMinLen - 2); ++i )
			m_pShiftTbl.insert( { strIter->substr( i, 2 ), m_iMinLen - 1} );	// Initialize a new Shift Table value for each two-byte identifier

	// Evaluate the Shift Table and populate the Hash Table
	for ( unordered_map< string, UINT >::iterator shiftIter = m_pShiftTbl.begin();
		  shiftIter != m_pShiftTbl.end();
		  ++shiftIter )
	{	// For each entry in the shift table calculate the nearest offset to a potential match
		for ( UINT i = 0; i < pMinLngthSubstrs.size(); ++i  )
		{
			// Calculate the q_xy (MINLEN - the distance from two-byte identifier to end of signature substring)
			q_xy = m_iMinLen - (pMinLngthSubstrs[i].rfind( shiftIter->first ) + 2);
			shiftIter->second = (q_xy < shiftIter->second ? q_xy : shiftIter->second);	// Keep the minimum
			if ( !q_xy )										
				m_pHashTbl[ shiftIter->first ].push_back( pKeys[i] );	// If q_xy == 0, store full string in the hash table as a potential hit.
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

// Scans a file and if a virus is found, return a list of potential viruses it could be.
void WuManber::scanFile( string sFileName, vector< string >& pPotentialHits )
{
  UINT iStart, iEnd;
  ifstream pFilePtr( sFileName );
  char sTwoByteBuffer[ 3 ] = { '\0' };
  string sTwoByte;
  vector< string > const *pHashResults;
  UINT i = m_iMinLen, iShift;
  m_pVDB->getMinMaxOffsets(iStart, iEnd);

  if( pFilePtr.is_open() )
    {
      while ( (iStart + i) < iEnd )
	  {
		  // Read Two Byte check
		  pFilePtr.seekg( iStart + i - 2 );
		  pFilePtr.get( sTwoByteBuffer, 3 );
		  sTwoByte.assign( sTwoByteBuffer, 2 );

		  try {		// Look up shift value.
			iShift = m_pShiftTbl.at( sTwoByte );
		  } catch ( const out_of_range& eOOR ) {	// No entry? safe to jump MINLEN - 1
			iShift = m_iMinLen - 1; 
		  }

		  // Found a Min Match
		  if ( 0 == iShift )
		  {
			  pHashResults = &(m_pHashTbl[ sTwoByte ]);			// get list of possible Matching entries
			  pFilePtr.seekg( iStart + i - m_iMinLen );		// Rewind to the start of the pattern matching for a match check.
			  match( &pFilePtr, pHashResults, pPotentialHits );	// Check if there's any matches
			  pFilePtr.seekg( iStart + i );						// Seek back to left off position
			  iShift = 1;										// Move one over to continue checking.
		  }

		  // Move forward.
		  i += iShift;	
	  }
      
	  // Close file
      pFilePtr.close();
    }
  else
  {
	  cout << "Error: Unable to open file: \"" << sFileName << "\"\n";
  }

  
}

void WuManber::match( ifstream* const pFP, vector< string > const * pVirusNames, vector< string >& pRetMatches )
{
	char cChr;
	UINT i = 0, indx = 0;
	string sComparator;
	vector< string > v_sComparingSigs;
	vector< string >::iterator iter;
	m_pVDB->getSignatures( v_sComparingSigs, pVirusNames );

	while ( !pFP->eof() )
	{
		pFP->get(cChr);
		for ( iter = v_sComparingSigs.begin();
			 iter != v_sComparingSigs.end(); )
		{
			if ( cChr != (*iter)[ i ] )
				iter = v_sComparingSigs.erase( iter );
			else if ( iter->length() == (i + 1) )
			{
				pRetMatches.push_back( (*pVirusNames)[ indx ] );
				iter = v_sComparingSigs.erase( iter );
			}
			else
			{
				++iter;
				++indx;
			}
		}
		++i;
		indx = 0;
		if ( v_sComparingSigs.empty() )
			break;
	}
}

void WuManber::fullScan( unordered_map< string/*File Name*/, vector< string > /*Resulting Viruses*/>& pResults )
{
	for ( string sDir : sDirectories )
	{
		scanDirectory( sDir, pResults );
	}
}

/* Algorithm pulled from https://stackoverflow.com/questions/306533/how-do-i-get-a-list-of-files-in-a-directory-in-c */
void WuManber::scanDirectory( const string& sDirectory, unordered_map< string/*File Name*/, vector< string > /*Resulting Viruses*/>& pResults )
{
	// Local Variables
	int iNumDots( 0 ), iMaxChars( 0 );
	class dirent *pEntry = NULL;
	class stat st;
	DIR *pDirectory = opendir( sDirectory.c_str() );
	vector< string > sPotentialHits;

	if ( NULL == pDirectory )
		fprintf( stderr, "Error: could not open directory: \"%s\" -> \"%s\"\n", sDirectory.c_str(), strerror( errno ) );
	else
	{
		while ( NULL != (pEntry = readdir( pDirectory )) )
		{
			const string sFileName = pEntry->d_name;
			const string sFullFileName = sDirectory + "/" + sFileName;

			if ( '.' == sFileName[ 0 ] )
				continue;

			// get info about file.
			if ( -1 == stat( sFullFileName.c_str(), &st ) )
			{
				fprintf( stderr, "Error: couldn't retrieve information about file \"%s\" -> \"%s\"\n", sFullFileName.c_str(), strerror( errno ) );
				continue;
			}

			if ( S_ISDIR( st.st_mode ) ) // Directory: Recurse
				scanDirectory( sFullFileName, pResults );
			else if ( S_ISREG( st.st_mode ) && isElf( sFullFileName ) )
			{
				// Output Scanning info
				iMaxChars = outputLoadBar( iNumDots, sFullFileName, iMaxChars );
				if ( NUM_ELIPSIS == (++iNumDots) )
					iNumDots = 0;

				// Scan the file.
				scanFile( sFullFileName, sPotentialHits );

				// Were there hits.
				if ( !sPotentialHits.empty() )
				{
					// Relay result.
					cout << "\"" << sFullFileName << "\" is potentially infected by: ";
					for ( vector< string >::iterator sIter = sPotentialHits.begin();
						 sIter != sPotentialHits.end();
						 ++sIter )
						cout << *sIter << ((sIter + 1) == sPotentialHits.end() ? ".\n" : ", ");

					// Insert into Results
					pResults.insert( make_pair( sFullFileName, sPotentialHits ) );
				}
			}
		} // end While

		// Clear Scanning Loadbar.
		for ( int i = 0; i < iMaxChars; ++i )
			cout << " ";
		cout << "\r";

		closedir( pDirectory );
	}
}

// Output Scanning Information.
int WuManber::outputLoadBar( int iNumDots, const string& sFileName, int iMaxChars )
{
	// Local Variables
	int iNewMaxChars = sFileName.length() + DEFAULT_NUM_LOAD_CHARS;

	// Output File being scanned.
	cout << "Scanning " << sFileName;

	// Output animating ellipsis
	for ( UBYTE i = 0; i < NUM_ELIPSIS; ++i )
		cout << (i < (iNumDots & (NUM_ELIPSIS - 1)) ? "." : " ");

	// Clear last characters that were printed.
	for ( UBYTE i = iMaxChars; i < iNewMaxChars; ++i )
		cout << " ";

	// Carriage return to overwrite line.
	cout << "\r";

	// Return new max for next call.
	return iNewMaxChars;
}

// checks a file to tell if it's an ELF file or not
bool WuManber::isElf( const string& sFileName )
{
	// Local Variables
	ifstream pFile( sFileName );
	UBYTE const * pPtr = sELF;
	bool bReturnValue = false;

	// Check if Open
	if ( pFile.is_open() )
	{
		// Set to true for short-circuit evaluation
		bReturnValue = true;
		
		// Check first 4 bytes.
		for ( UBYTE i = 0; i < NUM_ELF_BYTES; ++i )
			bReturnValue = bReturnValue && (*(pPtr++) == (UBYTE) pFile.get());

		// Close file.
		pFile.close();
	}

	// Return result.
	return bReturnValue;
}