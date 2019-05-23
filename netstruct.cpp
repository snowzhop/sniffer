#include "netstruct.hpp"
#include <pcap.h>
#include <iostream>
#include <netdb.h>
#include <ifaddrs.h>
#include <cstring>

const u_char ETH_HLEN = 14;

void my_callback(u_char *argc, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    static int count = 1;
    fprintf(stdout, "%3d, ", count);
    fflush(stdout);
    count++;
}

uint16_t getPort(const u_char* packet) {
    char ports[2];
    u_char* _packet = const_cast<u_char*>(packet);
    
    ports[0] = *_packet;
    _packet++;
    ports[1] = *_packet;
    uint16_t port = port & ports[0];
    port = port << 8;
    port = port & ports[1];
    port = ntohs(port);
    std::cout << std::endl << "----------" << std::endl;
    for(int j = 0; j < 2; j++) {
        int i = 128; 
        while(true) {
            if (ports[j] & i) {
                std::cout << "1";
            }
            else {
                std::cout << "0";
            }
            if (i == 1) break;
            i >>= 1;
        }
    }
    std::cout << std::endl << "----------" << std::endl;

    return port;
}

char* getHostAddr() {
    struct ifaddrs* ifaddr;
    struct ifaddrs* ifa;
    // char host[NI_MAXHOST];
    char* host = new char[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Error: getHostAddr(): getifaddrs" << std::endl;
        exit(EXIT_FAILURE);
    }

    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, "lo") != 0) {
            int s = getnameinfo(ifa->ifa_addr, 
                            sizeof(struct sockaddr_in),
                            host,
                            NI_MAXHOST, NULL,
                            0,
                            NI_NUMERICHOST);
            if (s != 0) {
                std::cerr << "Error: getHostAddr(): getnameinfo() failed: " << gai_strerror(s) << std::endl;
                exit(EXIT_FAILURE);
            }
            return host;
        }
    }
}

void another_callback(u_char *argc, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Vars for Bps analysis
    struct timeval *old_ts = (struct timeval *)argc;
    u_int delay;
    int64_t bps;

    static int count = 0;
    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];

    std::cout << std::dec << "Packet count: " << ++count << std::endl;
    std::cout << "Received Packet size: " << pkthdr->len << std::endl;
    std::cout << std::endl;

    const ip_h* ipHeader = (ip_h*)(packet + ETH_HLEN);
    int sizeIpHeader = ipHeader->getLen() * 4;

    const tcp_h* tcpHeader = (tcp_h*)(packet + ETH_HLEN + sizeIpHeader);
    int sizeTcpHeader = tcpHeader->getLen() * 4;
    
    if (inet_ntop(AF_INET, (in_addr*)&ipHeader->ip_src.s_addr, srcIp, sizeof(srcIp)) == NULL) {
        std::cerr << "Trouble: inet_ntop(src)" << std::endl;
    }

    if (inet_ntop(AF_INET, (in_addr*)&ipHeader->ip_dst.s_addr, dstIp, sizeof(dstIp)) == NULL) {
        std::cerr << "Trouble: inet_ntop(dst)" << std::endl;
    }

    //Bps analysis
    delay = (pkthdr->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + pkthdr->ts.tv_usec;

    std::cout << "IP header size: " << sizeIpHeader << std::endl; 
    std::cout << "TCP header size: " << sizeTcpHeader << std::endl;

    std::cout << "Address:" << std::endl;
    std::cout << "\tSource:" << std::endl << "\t\t" << srcIp 
                                        << "  " << ntohs(tcpHeader->tcp_srcp) << std::endl;
    std::cout << "\tDestination: " << std::endl << "\t\t" << dstIp 
                                        << "  " << ntohs(tcpHeader->tcp_dstp) << std::endl;

    std::cout << "IP checksum: " << std::hex << ipHeader->ip_chksm << std::endl;
    std::cout << "TCP checksum: " << tcpHeader->tcp_chksm << std::endl;
    std::cout << "Payload: ";
    if (ETH_HLEN + sizeIpHeader + sizeTcpHeader == pkthdr->len) {
        std::cout << "---" << std::endl;
    }
    else {
        int packetCounter = 0;
        const u_char* payload = packet + ETH_HLEN + sizeIpHeader + sizeTcpHeader;
        std::cout << std::endl << "\t";
        for(int i = 0; i < (pkthdr->len - (ETH_HLEN + sizeIpHeader + sizeTcpHeader)); i++) {
            if (isprint(packet[i])) {
                std::cout << packet[i] << " ";
            }
            else {
                std::cout << ". ";
            }
            packetCounter++;
            switch (packetCounter) {
                case 8: {
                    std::cout << "  ";
                    break;
                }
                case 16: {
                    std::cout << std::endl << "\t";
                    packetCounter = 0;
                    break;
                }
            }
        }
        std::cout << std::endl;
    }

    std::cout << "_____________" << std::endl << std::endl;
}