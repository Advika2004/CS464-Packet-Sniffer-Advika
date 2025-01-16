#include "trace.h"

int print_ethernet_header(const u_int8_t *payload){
    //cast the data ptr to a struct ptr so that the struct fields get filled with the right stuff
    struct ethernetHeader *eth_head = (struct ethernetHeader*)(payload);
    
    //start printing it out
    printf("Ethernet Header\n");
    printf("\tDest MAC: %s\n", ether_ntoa((struct ether_addr*)(&eth_head->macAddy)));
    printf("\tSource MAC: %s\n", ether_ntoa((struct ether_addr*)(&eth_head->destAddy)));

    uint16_t converted_type = ntohs(eth_head->type);

    //print the type but read byte by byte so no conversion needed
    if (converted_type == 0x0800){
        printf("\tType: IP\n\n"); 
    }
    else if (converted_type == 0x0806){
        printf("\tType: ARP\n\n");
    }
    else {
        printf("\tType: 0x%04x\n\n", converted_type);
    }
    return 0;
}

int print_packet_info(int count, int length){
    printf("Packet number: %d  Packet Len: %d\n\n", count, length);
    return 0;
}

