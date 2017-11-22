// Includes
#include "VirusDB.h"
#include <iostream>
#include <sstream>
#include <fstream>

// Defines
#define INPUT_SIZE 256
#define COMMENT '#'
#define VIRUS_NAME 'v'
#define SIGNATURE 's'
#define OFFSET 'o'
#define END '.'

// Constants
const char FILE_NAME[] = { "virus.db" };
const char VALID_CHARS[] = { "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" };

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
	VirusEntryStruct stEntry;
	istringstream ssStream;
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
						stEntry.m_sSignature.assign( pBeginIter + 2, pEndIter );
						break;
					case OFFSET:		// Assign Offset into the file.
						ssStream.str( sBuffer );
						ssStream.seekg( offsetBegin );
						ssStream >> stEntry.m_iOffset;
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
		for ( unordered_map<string, VirusEntryStruct>::iterator iter = m_Entries.begin();
			 iter != m_Entries.end();
			 ++iter )
		{
			cout << "Virus: " << (*iter).first << endl;
			cout << "\tSignature:\t" << (*iter).second.m_sSignature << endl;
			cout << "\tOffset:\t\t" << (*iter).second.m_iOffset << endl;
		}
	}
	else	// Unable to open the file.
		cout << "Error: unable to open " << FILE_NAME << endl;
}