#include "includes.h"
#include "VirusDB.h"
#include "WuManber.h"

const UBYTE sELF[] = { "\x7f\x45\x4c\x46" };

// Defines
#define NUM_ELF_BYTES 4

int main(int iArgc, char* sArgs[])
{
	// Local Variables
	VirusDB *pVDB = VirusDB::getInstance();
	WuManber *pWM = new WuManber();
	vector< string > pMatches;


	pWM->initialize( );


	if ( iArgc > 1 )
	{
		pWM->scanFile( sArgs[ 1 ], pMatches );

		if ( pMatches.empty() )
			cout << "\"" << sArgs[ 1 ] << "\" is not infected.\n";
		else
		{
			cout << "\"" << sArgs[ 1 ] << "\" is potentially infected by: \n";
			for ( vector< string >::iterator iter = pMatches.begin();
				 iter != pMatches.end();
				 ++iter )
				cout << "\t" << (*iter) << endl;
		}
	}

	delete pVDB;
	delete pWM;
    return 0;
}