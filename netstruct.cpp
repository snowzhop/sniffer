#include <pcap.h>
#include <iostream>
#include <ifaddrs.h>
#include <unistd.h>
#include <termios.h>
#include <thread>

#include "netstruct.hpp"

const u_char ETH_HLEN = 14;

void my_callback(u_char *argc, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    static int count = 1;
    fprintf(stdout, "%3d, ", count);
    fflush(stdout);
    count++;
}

char* getHostAddr() {   // Function for getting host address
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

void packetSniffing(char* address, u_char *argc, struct pcap_pkthdr* pkthdr, const u_char* packet) {
    u_int delay;
    struct timeval *old_ts = (struct timeval*)argc;
    // char* address = (char*)(argc + sizeof(struct timeval*));
    int64_t bps;

    static int count = 0;
    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];
    int sizeTr = 0;
    bool validProtocol = false;

    // std::cout << std::dec << "Address: " << address << std::endl;
    std::cout << std::dec << "Packet count: " << ++count << std::endl;
    std::cout << "Received Packet size: " << pkthdr->len << std::endl;

    const ip_h* ipHeader = (ip_h*)(packet + ETH_HLEN);  // IP
    int sizeIpHeader = ipHeader->getLen() * 4;

    // const tcp_h* tcpHeader = (tcp_h*)(packet + ETH_HLEN + sizeIpHeader);  // TCP
    // int sizeTcpHeader = tcpHeader->getLen() * 4;
    
    if (inet_ntop(AF_INET, (in_addr*)&ipHeader->ip_src.s_addr, srcIp, sizeof(srcIp)) == NULL) { // IP
        std::cerr << "Trouble: inet_ntop(src)" << std::endl;
    }

    if (inet_ntop(AF_INET, (in_addr*)&ipHeader->ip_dst.s_addr, dstIp, sizeof(dstIp)) == NULL) { // IP
        std::cerr << "Trouble: inet_ntop(dst)" << std::endl;
    }

    //Bps analysis
    delay = (pkthdr->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + pkthdr->ts.tv_usec;
    bps = (int64_t)(pkthdr->caplen * 1000000 / delay);

    if (strcmp(dstIp, address) == 0) {
        std::cout << "\tDownload speed: " << bps << " bytes per second | Delay: " 
            << delay << " microseconds" << std::endl;
    }
    else {
        std::cout << "\tUpload speed: " << bps << " bytes per second | Delay: " 
            << delay << " microseconds" << std::endl;
    }
    std::cout << std::endl;

    old_ts->tv_sec = pkthdr->ts.tv_sec;
    old_ts->tv_usec = pkthdr->ts.tv_usec;

    std::cout << "IP header size: " << sizeIpHeader << std::endl; 
    std::cout << "IP checksum: 0x" << std::hex << ipHeader->ip_chksm << std::dec << std::endl;

    switch(ipHeader->ip_prt) {  // Protocol analysis
        case 1: {
            std::cout << std::endl << "Protocol: ICMP" << std::endl;
            break;
        }
        case 2: {
            std::cout << std::endl << "Protocol: IGMP" << std::endl;
            break;
        }
        case 6: {
            std::cout << std::endl << "Protocol: TCP" << std::endl;
            const tcp_h* tcpHeader = (tcp_h*)(packet + ETH_HLEN + sizeIpHeader);  // TCP
            sizeTr = tcpHeader->getLen() * 4;

            std::cout << "TCP header size: " << sizeTr << std::endl;
            std::cout << "Address:" << std::endl;
            std::cout << "\tSource:" << std::endl << "\t\t" << srcIp 
                                        << "  " << ntohs(tcpHeader->tcp_srcp) << std::endl;
            std::cout << "\tDestination:" << std::endl << "\t\t" << dstIp 
                                        << "  " << ntohs(tcpHeader->tcp_dstp) << std::endl;
            std::cout << "TCP checksum: 0x" << std::hex << std::uppercase
                                        << tcpHeader->tcp_chksm << std::dec << std::endl;
            validProtocol = true;

            break;
        }
        case 17: {
            std::cout << std::endl << "Protocol: UDP" << std::endl;
            const udp_h* udpHeader = (udp_h*)(packet + ETH_HLEN + sizeIpHeader);
            sizeTr = udpHeader->getLen();

            std::cout << "UDP header size: " << sizeTr << std::endl;
            std::cout << "Address:" << std::endl;
            std::cout << "\tSource:" << std::endl << "\t\t" << srcIp
                                        << "  " << ntohs(udpHeader->udp_srcp) << std::endl;
            std::cout << "\tDestination:" << std::endl << "\t\t" << dstIp
                                        << "  " << ntohs(udpHeader->udp_dstp) << std::endl;
            std::cout << "UDP checksum: 0x" << std::hex 
                                        << udpHeader->udp_chks << std::dec << std::endl;
            validProtocol = true;

            break;
        }
        default: {
            std::cout << "Protocol: Undefined" << std::endl;
            break;
        }
    }

    // std::cout << "TCP header size: " << sizeTcpHeader << std::endl;

    // std::cout << "Address:" << std::endl;
    // std::cout << "\tSource:" << std::endl << "\t\t" << srcIp 
    //                                     << "  " << ntohs(tcpHeader->tcp_srcp) << std::endl;
    // std::cout << "\tDestination: " << std::endl << "\t\t" << dstIp 
    //                                     << "  " << ntohs(tcpHeader->tcp_dstp) << std::endl;

    // std::cout << "TCP checksum: " << tcpHeader->tcp_chksm << std::endl;
    if (validProtocol) {
        std::cout << "Payload: ";
        if (ETH_HLEN + sizeIpHeader + sizeTr == pkthdr->len) {
            std::cout << "---" << std::endl;
        }
        else {
            int byteCounter = 0;
            int allbytes = 0;
            const u_char* payload = packet + ETH_HLEN + sizeIpHeader + sizeTr;
            std::cout << std::endl << "\t";
            for(int i = 0; i < (pkthdr->len - (ETH_HLEN + sizeIpHeader + sizeTr)); i++) {
                if (isprint(packet[i])) {
                    std::cout << packet[i] << " ";
                }
                else {
                    std::cout << ". ";
                }
                allbytes++;
                byteCounter++;
                switch (byteCounter) {
                    case 8: {
                        std::cout << "  ";
                        break;
                    }
                    case 16: {
                        std::cout << std::endl << "\t";
                        byteCounter = 0;
                        break;
                    }
                }
                if (allbytes > 1560) { break; }
            }
            std::cout << std::endl;
        }
    }

    std::cout << "_____________" << std::endl << std::endl;
}

void catch_next(pcap_t* descr, u_char* argc) {
    const u_char* packet;
    struct pcap_pkthdr* pkthdr;
    int counter = 0;
    int res = -1;
    char* address = getHostAddr();
    char stopLogging = 0;

    std::thread keyCheckThd(readInputKey, std::ref(stopLogging));
    keyCheckThd.detach();

    while(!stopLogging) {
        memset(&pkthdr, 0, sizeof(pkthdr));
        if ( (res = pcap_next_ex(descr, &pkthdr, &packet)) == 1) {
            packetSniffing(address, argc, pkthdr, packet);
            counter++;
        } 
    }
}

void readInputKey(char &key) {
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;

    newt.c_lflag = ~ (ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    key = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}