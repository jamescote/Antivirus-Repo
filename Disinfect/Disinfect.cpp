#include "Disinfect.h"

/*
    Default constructor
*/
Disinfector::Disinfector()
{

}

/*
    initialize - not sure what we need to initialize, but handle it here!
*/
void Disinfector::initialize()
{


}

/*
    detect the type of the virus - will need to consult the detector
*/
Virus* Disinfector::detectVirus( std::string sFileName )
{
    cout << "In detect virus!" << endl;
    cout << "filename: " << sFileName << endl;

    return new Virus("ExampleName", 
            VirusType::PREPENDER,
            0x123456789ABCDEF,
            35565,
            "Mah Signature Brings all the Bois to the Yawwrd."
            );
}

void Disinfector::disinfect( Virus* virus )
{

}

/* 
    Handle cleanup
*/
Disinfector::~Disinfector(){}