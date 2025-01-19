#include "trace.h"
#include "checksum.h"

int print_packet_info(int count, int length){
    printf("Packet number: %d  Packet Len: %d\n\n", count, length);
    return 0;
}

int print_ethernet_header(const u_int8_t *payload){
    //cast the data ptr to a struct ptr so that the struct fields get filled with the right stuff
    struct ethernetHeader *eth_head = (struct ethernetHeader*)(payload);

    //! move the pointer to where IP starts
    place_in_packet += 14;
    
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

int print_ip_header(const u_int8_t *payload){
    
    struct ipHeader *ip_head = (struct ipHeader*)(payload);

    //? calcualte everything: 

    //mask the lower 4 bits then divide by 16
    //will make the lower 4 bits 0, and will then shift everything down by 4 places, so I only get the upper 4 bits
    uint8_t ip_version = (ip_head->versionAndHeaderLength & UPPPERNIBBLE) / 16;

    //multiply by 4 to get how many bytes there are 
    uint8_t ip_header_length = (ip_head->versionAndHeaderLength & LOWERNIBBLE) * 4;

    //get the upper 6 bits and the lower 2 bits for the DSC and ECN values from the one TOS byte
    uint8_t DSC = (ip_head->TOS & UPPER6BITS) / 4;
    uint8_t ECN = (ip_head->TOS & LOWER2BITS);

    //? print everything: 
    printf("IP Header\n");
    printf("\tIP Version: %d\n", ip_version);
    printf("\tHeader Len (bytes): %d\n", ip_header_length);
    printf("\tTOS subfields:\n");
    printf("\t\tDiffserv bits: %d\n", DSC);
    printf("\t\tECN bits: %d\n", ECN);
    printf("\tTTL: %d\n", ip_head->timeToLive);
    
    //protocol
    if(ip_head->protocol == 0x11){
        printf("\tProtocol: UDP\n");
    }
    else if (ip_head->protocol == 0x06){
        printf("\tProtocol: TCP\n");
    }
    else {
        printf("\tProtocol: 0x%x\n", ip_head->protocol);
    }
    
    //checksum
    if (in_cksum((unsigned short *)place_in_packet, ip_header_length) == 0) {

        printf("\tChecksum: Correct (0x%04x)\n", ntohs(ip_head->checksum));
    }
    else {
        printf("\tChecksum: Incorrect (0x%04x)\n", ntohs(ip_head->checksum));
    }

    printf("\tSender IP: %s\n", inet_ntoa(ip_head->senderIP));
    printf("\tDest IP: %s\n\n", inet_ntoa(ip_head->destIP));

    //! move the pointer past IP after done processing it
    place_in_packet += ip_head->totalLength;

    return 0;
}
