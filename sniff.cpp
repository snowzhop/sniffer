#include <pcap.h>
#include <iostream>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

void my_callback(u_char *argc, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    static int count = 1;
    fprintf(stdout, "%3d, ", count);
    fflush(stdout);
    count++;
}

void another_callback(u_char *argc, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    static int count = 0;

    std::cout << "Packet count: " << ++count << std::endl;
    std::cout << "Received Packet size: " << pkthdr->len << std::endl;
    std::cout << "Payload:" << std::endl;
    for(int i = 0; i < pkthdr->len; i++) {
        if (isprint(packet[i])) {
            std::cout << packet[i] << " ";
        }
        else {
            std::cout << " . " << packet[i];
        }
        if ((i % 16 == 0 && i != 0) || i == pkthdr->len - 1) {
            std::cout << std::endl;
        }
    }
}

int main(int argc, char **argv) {
    std::cout << "Let't try pcap" << std::endl;
    std::cout << "--------------" << std::endl;

    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char* packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;
    struct bpf_program fp;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;

    if (argc != 2) {
        fprintf(stdout, "Usage: %s \"expression\"\n", argv[0]);
        return 0;
    }

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }

    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    if(pcap_compile(descr, &fp, argv[1], 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }

    if (pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }

    pcap_loop(descr, -1, another_callback, NULL);

    return 0;
}