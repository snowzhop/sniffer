#ifndef NETSTRUCT_H
#define NETSTRUCT_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <cstring>

struct ip_h {
    u_char ip_vl; // Version number (4 bits) + header length (4 bits)
    u_char ip_srvtp; // Service type
    u_short ip_len; // Length
    u_short ip_idpckt; // Packet identifier
    u_short ip_offset; // Fragment offset (First 3 bits - flags)
    u_char ip_ttl; // Time to live
    u_char ip_prt; // Protocol
    u_short ip_chksm; // Checksum
    struct in_addr ip_src;
    struct in_addr ip_dst;

    u_char getLen() const {
        return ip_vl & 0x0F;
    }
};


struct tcp_h {
    u_short tcp_srcp; // Source port
    u_short tcp_dstp; // Destination port;
    u_int tcp_seq; // Sequence number
    u_int tcp_ack; // Acknowledgment number
    u_short tcp_doff; // Data offet + reserved + flags
    // u_char tcp_off; // Offset
    // u_char tcp_flags; // Flags
    u_short tcp_win; // Window
    u_short tcp_chksm; // Checksum
    u_short tcp_urgp; // Urgent pointer

    u_short getLen() const {
        return (tcp_doff & 0xF0) >> 4;
    }
};

void my_callback(u_char *argc, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void another_callback(u_char *argc, const struct pcap_pkthdr* pkthdr, const u_char* packet);
uint16_t getPort(const u_char* packet);
char* getHostAddr();

#endif