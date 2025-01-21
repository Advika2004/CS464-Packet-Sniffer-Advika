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
    where_ip_addys_are = place_in_packet + 12;
    place_in_packet += ip_header_length;
    //should point to where the addresses start

    //!TESTING: 
    // printf("Address of place_in_packet: %p\n", (void *)place_in_packet);
    // printf("Address of where_ip_addys_are: %p\n", (void *)where_ip_addys_are);
    // printf("Difference between pointers: %ld bytes\n", (long)(where_ip_addys_are - place_in_packet));


    if (ip_head->protocol == 0x11){
        print_udp_header(place_in_packet);
    }
    else if (ip_head->protocol == 0x06) {
        print_tcp_header(place_in_packet, ip_head);
    }

    return 0;
}

int print_udp_header(const u_int8_t *payload){

    struct udpHeader *udp_head = (struct udpHeader*)(payload);

    printf("UDP Header\n");

    if (ntohs(udp_head->sourcePort) == 0x0035){
        printf("\tSource Port: DNS\n"); 
    }
    else {
        printf("\tSource Port: %d\n", ntohs(udp_head->sourcePort));
    }

    if (ntohs(udp_head->destPort) == 0x0035){
        printf("\tDest Port: DNS\n\n"); 
    }
    else {
        printf("\tDest Port: %d\n\n", ntohs(udp_head->destPort));
    }

    // //! move the pointer past UDP? but is there anything after? don't I just move onto the next packet? 
    // place_in_packet += ntohs(udp_head->totalLength);

    return 0;
}

int print_tcp_header(const u_int8_t *payload, struct ipHeader* ip_head){

    struct tcpHeader *tcp_head = (struct tcpHeader*)(payload);

    printf("TCP Header\n");

    if (ntohs(tcp_head->sourcePort) == 0x0050){
        printf("\tSource Port: HTTP\n"); 
    }
    else {
        printf("\tSource Port: %d\n", ntohs(tcp_head->sourcePort));
    }

    if (ntohs(tcp_head->destPort) == 0x0050){
        printf("\tDest Port: HTTP\n"); 
    }
    else {
        printf("\tDest Port: %d\n", ntohs(tcp_head->destPort));
    }

    printf("\tSequence Number: %u\n", ntohl(tcp_head->sequenceNumber));

    printf("\tACK Number: %u\n", ntohl(tcp_head->ACKNumber));

    //extract the offset and the flags
    //the actual offset bits are only the upper nibble, the rest is the reserved bits
    //so isolate the upper nibble
    uint8_t data_offset = (((tcp_head->offset) & UPPPERNIBBLE) / 16) * 4;
    uint8_t flags = tcp_head->flags;

    printf("\tData Offset (bytes): %d\n", data_offset);

    //all the flags
    if (!(flags & SYN)){
        printf("\tSYN Flag: No\n");
    }
    else{
        printf("\tSYN Flag: Yes\n");
    }

    if (!(flags & RST)){
        printf("\tRST Flag: No\n");
    }
    else{
        printf("\tRST Flag: Yes\n");
    }
    
    if (!(flags & FIN)){
        printf("\tFIN Flag: No\n");
    }
    else{
        printf("\tFIN Flag: Yes\n");
    }

    if (!(flags & ACK)){
        printf("\tACK Flag: No\n");
    }
    else{
        printf("\tACK Flag: Yes\n");
    }

    printf("\tWindow Size: %d\n", ntohs(tcp_head->windowSize));

    int checksum_result = calculate_checksum(place_in_packet, ip_head);

    if (checksum_result == 0) {
        printf("\tChecksum: Correct (0x%04x)\n\n", ntohs(tcp_head->checksum));
    }
    else {
        printf("\tChecksum: Incorrect (0x%04x)\n\n", ntohs(tcp_head->checksum));
    }

    return 0;
}

int calculate_checksum(const u_int8_t *payload, struct ipHeader* ip_head) {

    //put together the pseudoheader
    //need to malloc space for my struct 
    //need to read out the senderIP and the destIP as 32 bits not in_addr type
    //maybe I keep a global pointer to where the IP src address data and destination address data are
    //move the global pointer from the end of IP back 64 bytes, then read forward 32 bytes

    struct pseudoIPHeader *pseudo_head = malloc(sizeof(struct pseudoIPHeader));
    
    if (pseudo_head == NULL) {
        perror("could not successfully malloc the pseudoheader");
        exit(EXIT_FAILURE);
    }
    
    uint16_t ip_total_length = ntohs(ip_head->totalLength);
    uint8_t ip_header_length = (ip_head->versionAndHeaderLength & LOWERNIBBLE) * 4;
   
    uint16_t tcp_total_length_host = ip_total_length - ip_header_length;
    uint16_t tcp_total_length_net = htons(tcp_total_length_host);

    uint32_t ip_src_addy;
    uint32_t ip_dest_addy;

    memcpy(&ip_src_addy, where_ip_addys_are, 4); 

    where_ip_addys_are += 4;

    memcpy(&ip_dest_addy, where_ip_addys_are, 4);

    pseudo_head->srcIP = ip_src_addy;
    pseudo_head->destIP = ip_dest_addy;
    pseudo_head->reservedBits = 0;
    pseudo_head->protocol = 6;
    pseudo_head->tcpLength = tcp_total_length_net;

    // //!DEBUG PRINT STATEMENTS FOR PSEUDOHEADER
    // printf("Debug: Pseudoheader\n");
    // printf("\tSource IP: %u (0x%x)\n", ntohl(pseudo_head->srcIP), ntohl(pseudo_head->srcIP));
    // printf("\tDestination IP: %u (0x%x)\n", ntohl(pseudo_head->destIP), ntohl(pseudo_head->destIP));
    // printf("\tReserved Bits: %d\n", pseudo_head->reservedBits);
    // printf("\tProtocol: 0x%x\n", pseudo_head->protocol);
    // printf("\tTCP Length (Network Order): 0x%x\n", pseudo_head->tcpLength);

    //? now that the pseudoheader is made, can create that buffer to hold all the tcp data
    //? then call checksum on the buffer and return the checksum value. 

    uint8_t *checksum_buffer = malloc(PSEUDOHEADER + tcp_total_length_host);

     if (checksum_buffer == NULL) {
        perror("could not successfully malloc the buffer");
        free(pseudo_head);
        exit(EXIT_FAILURE);
    }

    //copy the 12 bytes into the buffer
    memcpy(checksum_buffer, pseudo_head, PSEUDOHEADER);

    //copy the tcp header and data into the buffer
    memcpy(checksum_buffer + PSEUDOHEADER, place_in_packet, tcp_total_length_host);
    
    //!DEBIG PRINT
     // Print the buffer contents in hex
    printf("Debug: Checksum Buffer (Hex Dump):\n");
    for (int i = 0; i < PSEUDOHEADER + tcp_total_length_host; i++) {
        printf("%02x ", checksum_buffer[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
   
    int totalLength = PSEUDOHEADER + tcp_total_length_host;

    int result = in_cksum((unsigned short *)checksum_buffer, totalLength);

    free(pseudo_head);
    free(checksum_buffer);

    printf("RESULT: %d\n", result);
    return result;

}