#include <pcap.h>
#include <iostream>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "netstruct.hpp"

int main(int argc, char **argv) {
    std::cout << "Simple sniffer" << std::endl;

    char *dev;  // Название сетевого интерфейса
    char errbuf[PCAP_ERRBUF_SIZE];   // Буфер для текста ошибок
    pcap_t* descr;   // Идентификатор устройства
    const u_char* packet;  // 
    struct pcap_pkthdr hdr;   // Структура, в которой возвращается первый принятый пакет
    struct ether_header *eptr;  
    struct bpf_program fp;  // Указатель на составленную версию фильтра
    bpf_u_int32 maskp;  // Маска сети, с которой работает данный фильтр
    bpf_u_int32 netp;   // ip

    struct timeval st_ts;
    int status = 0;
    
    char* address = getHostAddr();
    std::cout << "Address: " << address << std::endl;
    std::cout << "Addr len: " << strlen(address) << std::endl;

    char* arguments = new char[sizeof(&st_ts) + strlen(address)];
    memcpy(arguments, &st_ts, sizeof(&st_ts));
    memcpy(arguments + sizeof(&st_ts), address, strlen(address) + 1);

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
        std::cerr << "Error pcap_open_live(): " << errbuf << std::endl;
        exit(1);
    }
    std::cout << "Handle device name: " << pcap_datalink_val_to_name(pcap_datalink(descr)) << std::endl;

    if(pcap_compile(descr, &fp, argv[1], 0, netp) == -1) {
        std::cerr << "Error calling pcap_compile: " << argv[1] << std::endl;
        exit(1);
    }

    if (pcap_setfilter(descr, &fp) == -1) {
        std::cerr << "Filter setting error" << std::endl;
        exit(1);
    }

    std::cout << "--------------" << std::endl;
    int counter = pcap_loop(descr, -1, another_callback, (u_char*)arguments);

    pcap_close(descr);

    return 0;
}