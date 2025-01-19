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

struct ipHeader {
    uint8_t versionAndHeaderLength; //first 4 bits is the version, next 4 bits is the length
    uint8_t TOS; //tos field, upper 6 bits = DSC and lower 2 bits = ECN
    uint16_t totalLength; //tells you total length in bytes
    uint16_t identfication;
    uint16_t flagsAndFragmentOffset;
    uint8_t timeToLive;
    uint8_t protocol;
    uint16_t checksum;
    struct in_addr senderIP;
    struct in_addr destIP;
}__attribute__((packed));


//macros
#define UPPPERNIBBLE 0xF0
#define LOWERNIBBLE 0x0F
#define UPPER6BITS 0x11111100
#define LOWER2BITS 0x00000011

//functions
int print_ethernet_header(const u_int8_t *payload);
int print_packet_info(int count, int length);
int print_ip_header(const u_int8_t *payload);


//global
const u_int8_t *place_in_packet;