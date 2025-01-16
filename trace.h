#include <pcap/pcap.h>
#include <stdint.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

//struct to hold the ethernet fields
struct ethernetHeader {
    uint8_t macAddy[6]; //MAC address (6 bytes)
    uint8_t destAddy[6]; //destination address (6 bytes)
    uint16_t type; 
}__attribute__((packed)); //should be 14b bytes total

//functions
int print_ethernet_header(const u_int8_t *payload);
int print_packet_info(int count, int length);