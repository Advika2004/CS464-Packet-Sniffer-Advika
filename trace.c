#include "trace.h"

int packet_counter = 0;

int main (int argc, char* argv[]) {
    
    //make sure that there are enough arguments provided
    if (argc != 2) {
        fprintf (stderr, "Invalid Number of Input Arguments\n");
        return 1;
    }

    //open the file
    char error_buf[PCAP_ERRBUF_SIZE];
    const char *file_name = argv[1];
    //(returns a handle?) 
    pcap_t *result = pcap_open_offline(file_name, error_buf);
    
    if (result == NULL) {
        fprintf (stderr, "Could Not Open File: %s\n", error_buf);
    }

    //go through the packets (store output value, the struct that holds packet data, and the pointer to the payload)
    //pcap_t *output = NULL;
    struct pcap_pkthdr *packet_metadata;
    const u_int8_t *packet_data;

    while (pcap_next_ex(result, &packet_metadata, &packet_data) > 0) {
        packet_counter++;
        int cur_packet_length = packet_metadata->len;
       
        //move the global pointer to be where the packet data starts
        place_in_packet = packet_data;

        print_packet_info(packet_counter, cur_packet_length);
        print_ethernet_header(packet_data);

        //ip header takes current place in the packet
        print_ip_header(place_in_packet);

    }
    
    //close the file
    pcap_close(result);
    return 0;
}
