// attack_detection.cpp

#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip6.h>

// detectar ataques
void detectAttack(const u_char* packetData) {
    struct iphdr* ipv4Header = (struct iphdr*)(packetData + sizeof(struct ethhdr));
    struct ip6_hdr* ipv6Header = (struct ip6_hdr*)(packetData + sizeof(struct ethhdr));

    // detecção de ataque: pacotes com tamanho anormalmente grande
    if (ipv4Header->version == 4 && ntohs(ipv4Header->tot_len) > 1500) {
        std::cout << "Ataque detectado: Pacote IPv4 muito grande!" << std::endl;
    }

    if (ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_IPV6 && ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen) > 1500) {
        std::cout << "Ataque detectado: Pacote IPv6 muito grande!" << std::endl;
    }

    if ((ipv4Header->version == 4 && ipv4Header->protocol == IPPROTO_ICMP) || 
        (ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6)) {
        std::cout << "Ataque detectado: Pacote ICMP inesperado!" << std::endl;
    }
}
