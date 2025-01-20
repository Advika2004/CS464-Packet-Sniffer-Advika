#include <pcap/pcap.h>
#include <stdint.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

//?structs
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

struct udpHeader{
    uint16_t sourcePort;
    uint16_t destPort;
    uint16_t totalLength;
    uint16_t checksum;
    //after the checksum is the UDP payload
}__attribute__((packed));

struct tcpHeader{
    uint16_t sourcePort;
    uint16_t destPort;
    uint32_t sequenceNumber;
    uint32_t ACKNumber;
    uint8_t offset;
    uint8_t flags;
    uint16_t totalLength;
    uint16_t checksum;
    //after the checksum is the UDP payload
}__attribute__((packed));

//?macros
#define UPPPERNIBBLE 0xF0
#define LOWERNIBBLE 0x0F

#define UPPER6BITS 0x11111100
#define LOWER2BITS 0x00000011

#define FIN 0x01 //0000 0001
#define SYN 0x02 //0000 0010
#define RST 0x04 //0000 0100
#define ACK 0x10
 //0000 1000


//?functions
int print_ethernet_header(const u_int8_t *payload);
int print_packet_info(int count, int length);
int print_ip_header(const u_int8_t *payload);
int print_udp_header(const u_int8_t *payload);
int print_tcp_header(const u_int8_t *payload, struct ipHeader* ip_head);


//?global
const u_int8_t *place_in_packet;