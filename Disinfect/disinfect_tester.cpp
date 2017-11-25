#include "Disinfect.h"
#include "Virus.h"
#include "types.h"
#include <iostream>

using namespace std;

int main(int argc, char* argv[]){
    if (argc != 2){
        cout << "Invalid usage." << endl;
        cout << "Proper usage: " << argv[0] << " [infected_file]" << endl;
        exit(1);
    }

    string sFileName = argv[1];

    Disinfector *pDisinfector = new Disinfector();
    Virus *pVirus = pDisinfector->detectVirus(sFileName);
    pVirus->toString();

    delete pVirus;
    delete pDisinfector;
    return 0;
}