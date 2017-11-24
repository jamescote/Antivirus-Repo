// Includes
#include "VirusDB.h"

// Defines
#define INPUT_SIZE 256
#define COMMENT '#'
#define VIRUS_NAME 'v'
#define SIGNATURE 's'
#define OFFSET 'o'
#define END '.'

// Constants
const char FILE_NAME[] = { "virus.db" };
const char VALID_CHARS[] = { "-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };

// Singleton Implementation
VirusDB* VirusDB::m_pInstance = NULL;

VirusDB* VirusDB::getInstance()
{
	if ( NULL == m_pInstance )
		m_pInstance = new VirusDB();
	return m_pInstance;
}

// Constructor
VirusDB::VirusDB()
{
	loadDB();	// Load in the virus.db file.
}

VirusDB::~VirusDB()
{
	// Nothing to Destruct
}

// Load the virus Database from the pre-defined FILE_NAME
void VirusDB::loadDB()
{
	// Local Variables
	ifstream pDBFile( FILE_NAME );
	string sBuffer;
	string::iterator pBeginIter, pEndIter;
	string sName;
	string sRawSig;
	VirusEntryStruct stEntry;
	istringstream isStream;
	stringstream sStream;
	size_t offsetBegin, offsetEnd;

	// Ensure file is open.
	if ( pDBFile.is_open() )
	{
		// Read until End of File.
		while ( !pDBFile.eof() )
		{
			// Get next line from the file.
			getline( pDBFile, sBuffer );

			// Handle input if not empty.
			if ( !sBuffer.empty() )
			{
				// Move through any leading whitespace.
				pBeginIter = sBuffer.begin();
				while ( isspace( *pBeginIter ) )
					++pBeginIter;
				
				// Isolate first argument following identifier.
				offsetBegin = (pBeginIter - sBuffer.begin()) + 2;
				offsetEnd = sBuffer.find_first_not_of( VALID_CHARS, offsetBegin );
				pEndIter = (offsetEnd == string::npos ? sBuffer.end() : sBuffer.begin() + offsetEnd);

				// Check delimiting character.
				switch ( *pBeginIter )
				{
					case VIRUS_NAME:	// Assign Virus Name
						sName.assign( pBeginIter + 2, pEndIter );
						break;
					case SIGNATURE:		// Assign Signature
						sRawSig.assign( pBeginIter + 2, pEndIter );
						if ( sRawSig.size() & 1 )
							sRawSig.push_back( '0' );
						UINT cByte;
						for ( UINT off = 0; off < sRawSig.length(); off += 2 )
						{
							sStream.clear();
							sStream << hex << sRawSig.substr( off, 2 );
							sStream >> cByte;
							stEntry.m_sSignature.push_back( static_cast<UBYTE>(cByte) );
						}
						break;
					case OFFSET:		// Assign Offset into the file.
						isStream.str( sBuffer );
						isStream.seekg( offsetBegin );
						isStream >> stEntry.m_iOffset;
						break;
					case END:			// Found an end, consolidate entry and store
						if ( !sName.empty() && !stEntry.m_sSignature.empty() )
							m_Entries.insert( { sName, stEntry } );

						// Reset entry parameters
						sName.clear();
						stEntry.m_sSignature.clear();
						stEntry.m_iOffset = 0;
						break;
					case COMMENT:
					default:
						break;
				}
			}
		}
		// close the file.
		pDBFile.close();

		// Debugging
	#ifdef DEBUG
		for ( unordered_map<string, VirusEntryStruct>::iterator iter = m_Entries.begin();
			 iter != m_Entries.end();
			 ++iter )
		{
			cout << "Virus: " << (*iter).first << endl;
			cout << "\tSignature:\t" << (*iter).second.m_sSignature << endl;
			cout << "\tOffset:\t\t" << (*iter).second.m_iOffset << endl;
		}
	#endif
	}
	else	// Unable to open the file.
		cout << "Error: unable to open " << FILE_NAME << endl;
}

// Gets a vector of signature strings.
void VirusDB::getSignatures( vector< string >& pSigs, vector< string > const *pKeys )
{
	if ( pKeys )	// Keys Specified? get the specific signatures
		for ( vector< string >::const_iterator iter = pKeys->begin();
			 iter != pKeys->end();
			 ++iter )
			pSigs.push_back( m_Entries[ (*iter) ].m_sSignature );
	else			// Get all the signatures
		for ( unordered_map<string, VirusEntryStruct>::iterator iter = m_Entries.begin();
			 iter != m_Entries.end();
			 ++iter )
			pSigs.push_back( iter->second.m_sSignature );
}

// Returns the range of the Offsets in the Virus Database
void VirusDB::getMinMaxOffsets( UINT& iMin, UINT& iMax )
{
	// Initialize to Max and Min possible
	iMin = numeric_limits<UINT>::max();
	iMax = 0;

	// Go through and evaluate min and max
	for ( unordered_map<string, VirusEntryStruct>::iterator iter = m_Entries.begin();
		  iter != m_Entries.end();
		  ++iter )
	{
		if ( iter->second.m_iOffset < iMin )
			iMin = iter->second.m_iOffset;
		if ( (numeric_limits<UINT>::max() != iter->second.m_iOffset) && ((iter->second.m_iOffset + iter->second.m_sSignature.length()) > iMax) )	// Ignore offsets set to MAX INT.
			iMax = iter->second.m_iOffset + iter->second.m_sSignature.length();
	}
}