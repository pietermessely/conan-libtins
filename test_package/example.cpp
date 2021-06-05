//#include "hello.h"
#include <iostream>
#include <tins/network_interface.h>
#include <tins/sniffer.h>
#include <tins/pdu.h>
//
int main() {
    //hello();
    Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
    std::cout << "We select interface with name: " << iface.name() << std::endl;
    
    Tins::Sniffer sniffer(iface.name());
    
    if(!iface.name().empty())
    {
    
        Tins::PDU *some_pdu = sniffer.next_packet();
        
        if(some_pdu)
        {
            
            std::cout << "Sniffed a random packet" << std::endl;
            delete some_pdu;        
            std::cout << "Success" << std::endl;
            return EXIT_SUCCESS;
        }
    }    
    else
    {
        std::cerr << "Couldn't select a network interface, might be because of the buildserver, so check the machine" << std::endl;
    }
    
    std::cerr << "Failed" << std::endl;
    return EXIT_FAILURE;
}
