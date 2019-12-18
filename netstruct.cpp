#include <pcap.h>
#include <iostream>
#include <ifaddrs.h>
#include <unistd.h>
#include <termios.h>
#include <thread>
#include <list>
#include <limits>
#include <fstream>
#include "discpp.h"

#include "netstruct.hpp"

const u_char ETH_HLEN = 14;
const int bSize = 50;

void my_callback(u_char *argc, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    static int count = 1;
    fprintf(stdout, "%3d, ", count);
    fflush(stdout);
    count++;
}

char* getHostAddr() {   // Function for getting host address
    struct ifaddrs* ifaddr;
    struct ifaddrs* ifa;
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

void packetSniffing(char* address, u_char *argc, struct pcap_pkthdr* pkthdr, const u_char* packet,
                                                                             std::list<int64_t> &delayList) {
    u_int delay;
    struct arg *old_ts = (struct arg*)argc;
    int64_t bps;

    static int count = 0;

    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];
    int sizeTr = 0;
    bool validProtocol = false;

    std::cout << std::dec << "Packet count: " << ++count << std::endl;
    std::cout << "Received Packet size: " << pkthdr->len << std::endl;

    const ip_h* ipHeader = (ip_h*)(packet + ETH_HLEN);  // IP
    int sizeIpHeader = ipHeader->getLen() * 4;
    
    if (inet_ntop(AF_INET, (in_addr*)&ipHeader->ip_src.s_addr, srcIp, sizeof(srcIp)) == NULL) { // IP
        std::cerr << "Trouble: inet_ntop(src)" << std::endl;
    }

    if (inet_ntop(AF_INET, (in_addr*)&ipHeader->ip_dst.s_addr, dstIp, sizeof(dstIp)) == NULL) { // IP
        std::cerr << "Trouble: inet_ntop(dst)" << std::endl;
    }

    //Bps analysis
    try {
        delay = (pkthdr->ts.tv_sec - old_ts->time.tv_sec) * 1000000 - old_ts->time.tv_usec + pkthdr->ts.tv_usec;
        if (delay != 0) {
            bps = (int64_t)(pkthdr->caplen * 1000000 / delay);
        }
        else {
            std::cout << "OPUCH" << std::endl;
        }
    }
    catch(...) {
        std::cout << "Error: BPS BPS | delay = 0" << std::endl;
        throw;
    }

    if (strcmp(dstIp, address) == 0) {
        std::cout << "\tDownload speed: " << bps << " bytes per second | Delay: " 
            << delay << " microseconds" << std::endl;
    }
    else {
        std::cout << "\tUpload speed: " << bps << " bytes per second | Delay: " 
            << delay << " microseconds" << std::endl;
    }

    try {
        old_ts->time.tv_sec = pkthdr->ts.tv_sec;
        old_ts->time.tv_usec = pkthdr->ts.tv_usec;
        old_ts->size += pkthdr->len;
    }
    catch(...) {
        std::cout << "Error: OLD TS OLD TS | delay = 0" << std::endl;
        throw;
    }

    std::cout << std::endl;
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
                if (allbytes > 1600) { break; }
            }
            std::cout << std::endl;
        }
    }
    delayList.push_back(delay);
    std::cout << "_____________" << std::endl << std::endl;
}   // packetSniffing(. . .)

void capture_next(pcap_t* descr, u_char* argc) {  // Packet capturing
    const u_char* packet;
    struct pcap_pkthdr* pkthdr;
    int counter = 0;
    int res = -1;
    char* address = getHostAddr();
    char stopLogging = 0;

    std::list<int64_t> delay;

    struct arg *old_ts = (struct arg*)argc;
    old_ts->size = 0;

    std::thread keyCheckThd(readInputKey, std::ref(stopLogging));
    keyCheckThd.detach();

    while(!stopLogging) {
        memset(&pkthdr, 0, sizeof(pkthdr));
        if ( (res = pcap_next_ex(descr, &pkthdr, &packet)) == 1) {
            packetSniffing(address, argc, pkthdr, packet, delay);
            counter++;
        } 
    }
    
    switch(stopLogging) {
        case 's': {
            int counter = 1;
            int64_t minDelay = std::numeric_limits<int64_t>::max();
            int64_t maxDelay = 0;
            for(int64_t d: delay) {
                if (counter > 1) { 
                    if (d > maxDelay) {
                        maxDelay = d;
                    }
                    else {
                        if (d < minDelay) {
                            minDelay = d;
                        }
                    }
                }
                counter++;
            }

            delay.pop_front();
            std::cout << std::endl << "average: " << std::endl << average(delay) << std::endl;
            fileLog(delay);

            break;
        }
        case 'g': {
            delay.pop_front();
            fileLogAndGraphCreating(delay);
            break;
        }
    }
    std::cout << std::endl << counter << " packets captured" << std::endl;
    
    if (counter != 0) {
        std::cout << "Average packet length: " << old_ts->size / counter << std::endl;
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

double average(const std::list<int64_t> &list) {
    int size = list.size();
    double res = 0;
    int counter = 1;
    for(int64_t i: list) {
        res += (double)i / size;
        
        counter++;
    }
    return res;
}

int64_t minElement(std::list<int64_t> list) {
    int64_t min = std::numeric_limits<int64_t>::max();
    for(int64_t d: list) {
        if (d < min) {
            min = d;
        }
    }
    return min;
}

int64_t maxElement(std::list<int64_t> list) {
    int64_t max = 0;
    for(int64_t d: list) {
        if (d > max) {
            max = d;
        }
    }
    return max;
}

void fileLog(const std::list<int64_t> &list) {
    std::ofstream output("log.csv", std::ios::out);
    std::ofstream graph("loggraph.csv", std::ios::out);

    int* buckets = nullptr;

    // double dif = (double)(maxElement(list) - minElement(list)) / bSize;

    std::cout << "Min: " << minElement(list) << std::endl 
            << "Max: " << maxElement(list) << std::endl;

    // for(int64_t d: list) {
    //     output << d << ";" << std::endl;
    //     int temp = dif;
    //     int counter = 0;
    //     while(temp < d) {
    //         counter++;
    //         temp += dif;
    //     }
    //     buckets[counter]++;
    // }

    buckets = getBuckets(list);

    for(int i = 0; i < bSize; i++) {
        graph << (double)buckets[i] / list.size() << ";" << std::endl;
    }
    
    output.close();
    graph.close();
    delete[] buckets;
}

void fileLogAndGraphCreating(const std::list<int64_t> &list) {
    fileLog(list);
    Dislin g;
    double yLower[bSize];
    double yUpper[bSize];
    double x[bSize];

    int* buckets = getBuckets(list);
    for(int i = 0; i < bSize; ++i) {
        yLower[i] = 0.0;
        yUpper[i] = static_cast<double>(buckets[i]) / list.size();
        x[i] = static_cast<double>(i) + 1.0;
    }

    g.scrmod("revers");
    g.setpag("da4l");
    g.metafl("cons");
    g.disini();
    // g.intax();
    g.ticks(1, "x");
    // g.axslen(2370, 1500);
    // g.titlin("DELAY", 3);

    double max = static_cast<double>(maxElement(list));

    // g.labels("none", "x");
    // g.labels("none", "y");
    g.graf(0, bSize + 1, 0, 5, 0, 1, 0, 0.2);

    g.labels("none", "bars");
    g.labpos("outside", "bars");
    g.color("red");
    g.bars(x, yLower, yUpper, 10);

    g.endgrf();
    g.disfin();
}

int* getBuckets(const std::list<int64_t> &list) {
    int* buckets = new int[bSize];
    for(int i = 0; i < bSize; ++i) {
        buckets[i] = 0;
    }

    double dif = (double)(maxElement(list) - minElement(list)) / bSize;

    for(int64_t d: list) {
        int temp = dif;
        int counter = 0;
        while(temp < d) {
            counter++;
            temp += dif;
        }
        buckets[counter]++;
    }

    return buckets;
}