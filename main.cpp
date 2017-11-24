#include "includes.h"
#include "VirusDB.h"
#include "WuManber.h"

int main()
{
	VirusDB *pVDB = VirusDB::getInstance();
	WuManber *pWM = new WuManber();

	pWM->initialize( );

	delete pVDB;
	delete pWM;
    return 0;
}