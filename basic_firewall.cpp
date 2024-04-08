#include <iostream>
#include <fstream>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <ctime>
#include "attack_detection.cpp"

using namespace std;

struct FirewallRule {
    string srcIP;
    string destIP;
    int srcPort;
    int destPort;
    int protocol;
};

// regra de firewall
bool matchesRule(const FirewallRule& rule, const u_char* packetData) {
    struct iphdr* ipv4Header = (struct iphdr*)(packetData + sizeof(struct ethhdr));
    struct ip6_hdr* ipv6Header = (struct ip6_hdr*)(packetData + sizeof(struct ethhdr));

    if (ipv4Header->version == 4) {
        struct in_addr srcAddr = { ipv4Header->saddr };
        struct in_addr destAddr = { ipv4Header->daddr };

        if (rule.srcIP != "" && rule.srcIP != inet_ntoa(srcAddr))
            return false;

        if (rule.destIP != "" && rule.destIP != inet_ntoa(destAddr))
            return false;
    } else if (ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_IPV6) {
        struct in6_addr srcAddr = ipv6Header->ip6_src;
        struct in6_addr destAddr = ipv6Header->ip6_dst;

        char srcIP[INET6_ADDRSTRLEN];
        char destIP[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &srcAddr, srcIP, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &destAddr, destIP, INET6_ADDRSTRLEN);

        if (rule.srcIP != "" && rule.srcIP != srcIP)
            return false;

        if (rule.destIP != "" && rule.destIP != destIP)
            return false;
    }

    // protocolo corresponde à regra de firewall
    if (rule.protocol != 0 && rule.protocol != (ipv4Header->version == 4 ? ipv4Header->protocol : ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt))
        return false;

    // Implemente a lógica de filtragem de portas aqui

    return true;
}

// Função para tratar pacotes capturados
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    // Exemplo de regra de firewall (permitindo todos os pacotes TCP de origem 192.168.0.1 e destino 8.8.8.8)
    FirewallRule rule;
    rule.srcIP = "192.168.0.1";
    rule.destIP = "8.8.8.8";
    rule.srcPort = 0;
    rule.destPort = 0;
    rule.protocol = IPPROTO_TCP;

    // Verifica se o pacote corresponde à regra de firewall
    if (matchesRule(rule, packetData)) {
        cout << "Pacote permitido:" << endl;
    } else {
        cout << "Pacote bloqueado:" << endl;
        
        // Grava informações do pacote no log
        ofstream logfile("firewall_log.txt", ios::app);
        if (logfile.is_open()) {
            logfile << "Pacote bloqueado em: " << time(nullptr) << endl;
            logfile << "Tamanho do pacote: " << pkthdr->len << " bytes" << endl;
            // Adicione mais informações ao log, se necessárioo
            logfile << "--------------------------------------" << endl;
            logfile.close();
        } else {
            cerr << "Erro ao abrir o arquivo de log." << endl;
        }
    }

    // exibe informações 
    cout << "Tamanho do pacote: " << pkthdr->len << " bytes" << endl;
    cout << "--------------------------------------" << endl;
}

int main() {
    pcap_t* pcapHandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Abre a interface de rede para captura
    pcapHandle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (pcapHandle == nullptr) {
        cerr << "Erro ao abrir a interface de rede: " << errbuf << endl;
        return 1;
    }

    // Captura pacotes indefinidamente
    pcap_loop(pcapHandle, -1, packetHandler, nullptr);

    pcap_close(pcapHandle);

    return 0;
}
