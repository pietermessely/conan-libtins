//#include "hello.h"
#include <iostream>
#include <tins/network_interface.h>
#include <tins/config.h>
#include <tins/sniffer.h>
#include <tins/pdu.h>
#include <tins/rawpdu.h>
#include <tins/utils.h>
//
int main() {
    //hello();
    
    std::cout << "LibTins V" << TINS_VERSION_MAJOR << "." << TINS_VERSION_MINOR << "." << TINS_VERSION_PATCH << std::endl;
    
    Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
    std::cout << "We select interface with name: " << iface.name() << std::endl;
    
    Tins::Sniffer sniffer(iface.name());
    
    if(!iface.name().empty())
    {
    
        Tins::PDU *some_pdu = sniffer.next_packet();
        
        if(some_pdu)
        {
            std::cout << "Sniffed a random packet: pdu_type: " <<  Tins::Utils::to_string(some_pdu->pdu_type()) << std::endl;
            
            const Tins::RawPDU *raw = some_pdu->find_pdu<Tins::RawPDU>();
            std::cout <<"RawPDU header_size: " << raw->header_size() << std::endl;
            std::cout <<"RawPDU payload_size: " << raw->payload_size() << std::endl;
            std::cout <<"RawPDU payload().size(): " << raw->payload().size() << std::endl;
            std::vector<uint8_t> buffer = raw->payload();
            std::cout << std::endl;

            for (int i =0; i < buffer.size(); i++ ){
                std::cout << std::hex << static_cast<int>(buffer[i]);
                std::cout << " ";
            }
            std::cout << std::endl;
            


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
