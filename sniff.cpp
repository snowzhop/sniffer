#include <pcap.h>
#include <iostream>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "netstruct.hpp"

int main(int argc, char **argv) {
    std::cout << "Let's try pcap..." << std::endl;
    std::cout << "Ethernet header = " << ETH_HLEN << std::endl;

    int i;
    char *dev;  // Название сетевого интерфейса
    char errbuf[PCAP_ERRBUF_SIZE];   // Буфер для текста ошибок
    pcap_t* descr;   // Идентификатор устройства
    const u_char* packet;  // 
    struct pcap_pkthdr hdr;   // Структура, в которой возвращается первый принятый пакет
    struct ether_header *eptr;  
    struct bpf_program fp;  // Указатель на составленную версию фильтра
    bpf_u_int32 maskp;  // Маска сети, с которой работает данный фильтр
    bpf_u_int32 netp;   // ip

    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " \"expression\"" << std::endl;
        return 0;
    }

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {
        std::cerr << errbuf << std::endl;
        exit(1);
    }

    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    if(descr == NULL) {
        std::cout << "pcap_open_live(): " << errbuf << std::endl;
        exit(1);
    }
    std::cout << "Handle device name: " << pcap_datalink_val_to_name(pcap_datalink(descr)) << std::endl;

    if(pcap_compile(descr, &fp, argv[1], 0, netp) == -1) {
        std::cerr << "Error calling pcap_compile: " << argv[1] << std::endl;
        exit(1);
    }

    if (pcap_setfilter(descr, &fp) == -1) {
        std::cerr << "Error setting filter" << std::endl;
        exit(1);
    }

    std::cout << "--------------" << std::endl;
    int counter = pcap_loop(descr, -1, another_callback, NULL);

    return 0;
}