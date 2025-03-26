/*
 * FIT VUT - ISA 2022 - Generovani NetFlow dat ze zachycene sitove komunikace
  @author Adrián Bobola (xbobol00)
 */

#include <iostream>
#include <pcap.h>
#include <regex>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "flow.hpp"

using namespace std;

int exported_flows_cnt = 0;
int loaded_packets_cnt = 0;
long first_flow_SysTime = 0.0;
std::map<tuple<std::string, std::string, short unsigned int, short unsigned int, std::string, int>, One_flow_params> map_of_all_flows;
struct run_params params = {"-", "127.0.0.1", "2055", 60000000, 10000000, 1024};

int main(int argc, char **argv) {
    // Parsing arguments
    params_parser(argc, argv);

    // pcap_open_offline
    char err_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *packet;
    packet = pcap_open_offline(params.file_name.c_str(), err_buffer);
    if (packet == nullptr) {
        printf("Error packet open. FILE NOT FOUND! - pcap_open_offline\n");
        exit(1);
    }

    // pcap_setfilter to TCP, UDP or ICMP
    struct bpf_program bpf_program{};
    std::string filter = "tcp || udp || icmp";
    if (pcap_compile(packet, &bpf_program, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error pcap filter compile - pcap_compile\n");
        exit(1);
    }
    if (pcap_setfilter(packet, &bpf_program) == -1) {
        printf("Error pcap set filter - pcap_setfilter\n");
        exit(1);
    }

    // pcap_loop
    if (pcap_loop(packet, 0, packet_parser, nullptr) < 0) {
        printf("Error - pcap_loop\n");
        return 1;
    }
    // close packet and export flows cache
    pcap_close(packet);
    export_full_flows_cache();
    return 0;
}

/**
 * Parsing command-line options
 * @param argc - argument count
 * @param argv - argument vector
 */
void params_parser(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "f:c:a:i:m:")) != -1) {
        switch (opt) {
            case 'f':
                params.file_name = optarg;
                break;
            case 'c': {
                // convert hostname to IP and Port
                struct hostent *hp;
                struct in_addr ip_addr{};
                const char port_separator[2] = ":";
                char *domain = optarg;
                char *ipv4 = strtok(domain, port_separator);
                char *port = strtok(nullptr, ":");

                if (gethostbyname(ipv4) == nullptr) {
                    fprintf(stderr, "ERROR: Option \"-c\" has a invalid hostname\n");
                    exit(1);
                } else {
                    hp = gethostbyname(ipv4);
                }
                ip_addr = *(struct in_addr *) (hp->h_addr);
                params.ip = inet_ntoa(ip_addr);
                if (port != nullptr) {
                    params.port = port;
                }
                break;
            }
            case 'a':
                for (int i = 0; i < (int) strlen(optarg); i++) {
                    if (!isdigit(optarg[i])) {
                        fprintf(stderr, "ERROR: Option \"-a\" can not contain a character, only number is allowed\n");
                        exit(1);
                    }
                }
                params.active_timer = (atoi(optarg) * 1000000);
                break;
            case 'i':
                for (int i = 0; i < (int) strlen(optarg); i++) {
                    if (!isdigit(optarg[i])) {
                        fprintf(stderr, "ERROR: Option \"-i\" can not contain a character, only number is allowed\n");
                        exit(1);
                    }
                }
                params.inactive_timer = (atoi(optarg) * 1000000);
                break;
            case 'm':
                for (int i = 0; i < (int) strlen(optarg); i++) {
                    if (!isdigit(optarg[i])) {
                        fprintf(stderr, "ERROR: Option \"-m\" can not contain a character, only number is allowed\n");
                        exit(1);
                    }
                }
                if (atoi(optarg) == 0) {
                    fprintf(stderr, "ERROR: Option \"-m\" can not be a zero.\n");
                    exit(1);
                }
                params.flow_cache_size = atoi(optarg);
                break;
            default:
                fprintf(stderr, "ERROR: Unknow option: \"%c\"\n", optopt);
                exit(1);
        }
    }
}

/**
 * Parsing one packet - function called from pcap_loop
 * @param args - Non-Keyword Arguments
 * @param header - packet header
 * @param packet - packet
 */
void packet_parser(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header;

    // Set IP header
    ip_header = (struct ip *) (packet + sizeof(struct ether_header));
    // Set IP protocol
    int ip_protocol = ip_header->ip_p;

    // Set sysUptime from first packet
    if (loaded_packets_cnt == 0) {
        first_flow_SysTime = (header->ts.tv_usec / 1000) + (header->ts.tv_sec * 1000);
        loaded_packets_cnt++;
    }

    // ICMP
    if (ip_protocol == 1) {
        struct icmphdr *icmp_header;
        icmp_header = (struct icmphdr *) (packet + (ip_header->ip_hl * 4) + sizeof(struct ethhdr));
        actual_time.tv_usec = header->ts.tv_usec;
        actual_time.tv_sec = header->ts.tv_sec;
        check_timers(actual_time);
        // create a map key
        std::tuple<std::string, std::string, short unsigned int, short unsigned int, std::string, int> mapKey;
        mapKey = make_tuple(inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst), 0, 0, "ICMP", ip_header->ip_tos);

        // Find a map key in map
        auto it = map_of_all_flows.find(mapKey);
        if (it != map_of_all_flows.end()) {
            // mapKey exists in a map of flows, get params and change it
            One_flow_params flowParams = it->second;
            // set new flow values
            flowParams.srcIp = ntohl(ip_header->ip_src.s_addr);
            flowParams.destIp = ntohl(ip_header->ip_dst.s_addr);
            flowParams.srcPort = 0;
            flowParams.destPort = 0;
            flowParams.prot = ip_header->ip_p;
            flowParams.tos = ip_header->ip_tos;
            flowParams.Last.tv_sec = header->ts.tv_sec;
            flowParams.Last.tv_usec = header->ts.tv_usec;
            flowParams.dPkts += 1;
            flowParams.dOctets += ntohs(ip_header->ip_len);
            flowParams.tcp_flags = 0;

            it->second = flowParams;
        } else {
            // mapKey does not exist in a map of flows, insert new flow into map
            One_flow_params flowParams = {ntohl(ip_header->ip_src.s_addr), ntohl(ip_header->ip_dst.s_addr),
                                          0, 0, ip_header->ip_p, ip_header->ip_tos,
                                          header->ts.tv_sec, header->ts.tv_usec, header->ts.tv_sec,
                                          header->ts.tv_usec, 1, ntohs(ip_header->ip_len), 0};

            // Check flow cache size then insert new flow
            check_cache_size();
            map_of_all_flows.insert(std::make_pair(mapKey, flowParams));
        }
    }
        // TCP
    else if (ip_protocol == 6) {
        struct tcphdr *tcp_header;
        tcp_header = (struct tcphdr *) (packet + (ip_header->ip_hl * 4) + sizeof(struct ethhdr));
        u_int8_t tcp_flags = tcp_header->fin | tcp_header->syn << 1 | tcp_header->rst << 2 | tcp_header->psh << 3 |
                             tcp_header->ack << 4 | tcp_header->urg << 5;

        actual_time.tv_usec = header->ts.tv_usec;
        actual_time.tv_sec = header->ts.tv_sec;
        check_timers(actual_time);
        // create a map key
        std::tuple<std::string, std::string, short unsigned int, short unsigned int, std::string, int> mapKey;
        mapKey = make_tuple(inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst), tcp_header->source,
                            tcp_header->dest, "TCP", ip_header->ip_tos);

        // Find a map key in map
        auto it = map_of_all_flows.find(mapKey);
        if (it != map_of_all_flows.end()) {
            // mapKey exists in a map of flows, get params and change it
            One_flow_params flowParams = it->second;
            // set new flow values
            flowParams.srcIp = ntohl(ip_header->ip_src.s_addr);
            flowParams.destIp = ntohl(ip_header->ip_dst.s_addr);
            flowParams.srcPort = ntohs(tcp_header->source);
            flowParams.destPort = ntohs(tcp_header->dest);
            flowParams.prot = ip_header->ip_p;
            flowParams.tos = ip_header->ip_tos;
            flowParams.Last.tv_sec = header->ts.tv_sec;
            flowParams.Last.tv_usec = header->ts.tv_usec;
            flowParams.dPkts += 1;
            flowParams.dOctets += ntohs(ip_header->ip_len);
            flowParams.tcp_flags = flowParams.tcp_flags | tcp_flags;

            it->second = flowParams;

            // Check TCP flags - FIN
            if (tcp_flags & 0x01) {
                std::map<tuple<std::string, std::string, short unsigned int, short unsigned int, std::string, int>,
                        One_flow_params>::iterator
                        iterate;

                export_flow(&flowParams);
                iterate = map_of_all_flows.find(mapKey);
                map_of_all_flows.erase(iterate);
            }
                // Check TCP flags - RST
            else if (tcp_flags & 0x04) {
                std::map<tuple<std::string, std::string, short unsigned int, short unsigned int, std::string, int>,
                        One_flow_params>::iterator
                        iterator2;

                export_flow(&flowParams);
                iterator2 = map_of_all_flows.find(mapKey);
                map_of_all_flows.erase(iterator2);
            }

        }
            // mapKey does not exist in a map of flows, insert new flow into map
        else {
            One_flow_params flowParams = {ntohl(ip_header->ip_src.s_addr), ntohl(ip_header->ip_dst.s_addr),
                                          ntohs(tcp_header->source), ntohs(tcp_header->dest), ip_header->ip_p,
                                          ip_header->ip_tos,
                                          header->ts.tv_sec, header->ts.tv_usec, header->ts.tv_sec,
                                          header->ts.tv_usec, 1, ntohs(ip_header->ip_len), tcp_flags};

            // Check flow cache size then insert new flow
            check_cache_size();

            // Check TCP flags - FIN
            if (tcp_flags & 0x01) {
                export_flow(&flowParams);
            } // Check TCP flags - RST
            else if (tcp_flags & 0x04) {
                export_flow(&flowParams);
            } else {
                map_of_all_flows.insert(std::make_pair(mapKey, flowParams));
            }
        }
    }
        // UDP
    else if (ip_protocol == 17) {
        struct udphdr *udp_header;
        udp_header = (struct udphdr *) (packet + (ip_header->ip_hl * 4) + sizeof(struct ethhdr));
        actual_time.tv_usec = header->ts.tv_usec;
        actual_time.tv_sec = header->ts.tv_sec;
        check_timers(actual_time);
        // create a map key
        std::tuple<std::string, std::string, short unsigned int, short unsigned int, std::string, int> mapKey;
        mapKey = make_tuple(inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst), udp_header->source,
                            udp_header->dest, "UDP", ip_header->ip_tos);

        // Find a map key in map
        auto it = map_of_all_flows.find(mapKey);
        if (it != map_of_all_flows.end()) {
            // mapKey exists in a map of flows, get params and change it
            One_flow_params flowParams = it->second;
            // set new flow values
            flowParams.srcIp = ntohl(ip_header->ip_src.s_addr);
            flowParams.destIp = ntohl(ip_header->ip_dst.s_addr);
            flowParams.srcPort = ntohs(udp_header->source);
            flowParams.destPort = ntohs(udp_header->dest);
            flowParams.prot = ip_header->ip_p;
            flowParams.tos = ip_header->ip_tos;
            flowParams.Last.tv_sec = header->ts.tv_sec;
            flowParams.Last.tv_usec = header->ts.tv_usec;
            flowParams.dPkts += 1;
            flowParams.dOctets += ntohs(ip_header->ip_len);
            flowParams.tcp_flags = 0;

            it->second = flowParams;
        }
            // mapKey does not exist in a map of flows, insert new flow into map
        else {
            One_flow_params flowParams = {ntohl(ip_header->ip_src.s_addr), ntohl(ip_header->ip_dst.s_addr),
                                          ntohs(udp_header->source), ntohs(udp_header->dest), ip_header->ip_p,
                                          ip_header->ip_tos,
                                          header->ts.tv_sec, header->ts.tv_usec, header->ts.tv_sec,
                                          header->ts.tv_usec, 1, ntohs(ip_header->ip_len), 0};

            // Check flow cache size then insert new flow
            check_cache_size();
            map_of_all_flows.insert(std::make_pair(mapKey, flowParams));
        }
    }
}

/**
 * Checking First and Last timer for every stored flow.
 *  If flow stored time is more than active or inactive timer, then delete it from flow cache
 * @param actualFlowTime - actual packet time in timeval struct
 */
void check_timers(timeval actualFlowTime) {
    // iterate through all stored flows in map
    for (auto it = map_of_all_flows.begin(); it != map_of_all_flows.cend();) {
        One_flow_params OneFlowParams = it->second;

        long time_diff_last_first = ((OneFlowParams.Last.tv_sec * 1000000) + OneFlowParams.Last.tv_usec) -
                                    ((OneFlowParams.First.tv_sec * 1000000) + OneFlowParams.First.tv_usec);

        long time_diff_actual_last = ((actualFlowTime.tv_sec * 1000000) + actualFlowTime.tv_usec) -
                                     ((OneFlowParams.Last.tv_sec * 1000000) + OneFlowParams.Last.tv_usec);

        // Check active timer
        if (abs(time_diff_last_first) >= params.active_timer) {
            // add flow to export
            export_flow(&OneFlowParams);
            map_of_all_flows.erase(it++);
        }
            // Check inactive timer
        else if (abs(time_diff_actual_last) >= params.inactive_timer) {
            // add flow to export
            export_flow(&OneFlowParams);
            map_of_all_flows.erase(it++);
        } else {
            ++it;
        }
    }
}

/**
 * Checking number of Flows stored in cache
 *  If nb. of stored flows is more than -m param, then export first item from map
 */
void check_cache_size() {
    if (map_of_all_flows.size() >= params.flow_cache_size) {
        std::tuple<std::string, std::string, short unsigned int, short unsigned int, std::string, int> the_oldest_flow_map_key;
        One_flow_params the_oldest_flow_params{};
        // max long value
        long min_SysUptime = 9223372036854775807;

        // iterate through all stored flows in map to find the oldest inactive flow
        for (auto it = map_of_all_flows.begin(); it != map_of_all_flows.cend();) {
            One_flow_params one_flow_parameters = it->second;

            // If found the oldest flow then save its map key
            if (((one_flow_parameters.Last.tv_sec * 1000000) + one_flow_parameters.Last.tv_usec) <= min_SysUptime) {
                min_SysUptime = ((one_flow_parameters.Last.tv_sec * 1000000) + one_flow_parameters.Last.tv_usec);
                the_oldest_flow_map_key = it->first;
                the_oldest_flow_params = it->second;
            }
            ++it;
        }
        // Now we have the oldest flow in flow-cache. We can export it from cache to collector
        export_flow(&the_oldest_flow_params);
        map_of_all_flows.erase(the_oldest_flow_map_key);
    }
}

/**
 * Send one flow to collector via UDP
 * @param OneFlowParams - One_flow_params struct from sending flow
 */
void export_flow(One_flow_params *OneFlowParams) {
    flow_v5_export new_flow_struct{};

    // Flow Header
    new_flow_struct.version = htons(5);
    new_flow_struct.count = htons(1);
    new_flow_struct.sysUptime = htonl(
            ((OneFlowParams->Last.tv_usec / 1000) + (OneFlowParams->Last.tv_sec * 1000) - first_flow_SysTime));
    new_flow_struct.unix_secs = htonl(OneFlowParams->Last.tv_sec);
    new_flow_struct.unix_nsecs = htonl(OneFlowParams->Last.tv_usec * 1000);
    new_flow_struct.flow_sequence = htonl(exported_flows_cnt);
    new_flow_struct.engine_type = 0;
    new_flow_struct.engine_id = 0;
    new_flow_struct.sampling_interval = htons(0);

    // Flow Record
    new_flow_struct.srcaddr = htonl(OneFlowParams->srcIp);
    new_flow_struct.dstaddr = htonl(OneFlowParams->destIp);
    new_flow_struct.nexthop = htonl(0);
    new_flow_struct.input = htons(0);
    new_flow_struct.output = htons(0);
    new_flow_struct.dPkts = htonl(OneFlowParams->dPkts);
    new_flow_struct.dOctets = htonl(OneFlowParams->dOctets);
    new_flow_struct.First = htonl(
            (OneFlowParams->First.tv_usec / 1000) + (OneFlowParams->First.tv_sec * 1000) - first_flow_SysTime);
    new_flow_struct.Last = htonl(
            ((OneFlowParams->Last.tv_usec / 1000) + (OneFlowParams->Last.tv_sec * 1000) - first_flow_SysTime));
    new_flow_struct.srcport = htons(OneFlowParams->srcPort);
    new_flow_struct.dstport = htons(OneFlowParams->destPort);
    new_flow_struct.pad1 = 0;
    new_flow_struct.tcp_flags = OneFlowParams->tcp_flags;
    new_flow_struct.prot = OneFlowParams->prot;
    new_flow_struct.tos = OneFlowParams->tos;
    new_flow_struct.src_as = htons(0);
    new_flow_struct.dst_as = htons(0);
    new_flow_struct.src_mask = 0;
    new_flow_struct.dst_mask = 0;
    new_flow_struct.pad2 = htons(0);

    int sock;
    struct sockaddr_in server{};
    struct hostent *servent;

    // Erase server struct
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(atoi(params.port.data()));
    servent = gethostbyname(params.ip.data());
    memcpy(&server.sin_addr, servent->h_addr, servent->h_length);

    // Create a client socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        fprintf(stderr, "ERROR: Socket() failed\n");
        exit(1);
    }

    // Create a connected UDP socket
    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) == -1) {
        fprintf(stderr, "ERROR: Connect to sertver failed\n");
        exit(1);
    }

    // Send connected UDP socket to collector
    if (send(sock, &new_flow_struct, sizeof(new_flow_struct), 0) == -1) {
        fprintf(stderr, "ERROR: Sent to collector failed\n");
        exit(1);
    }

    // Close socked
    if (close(sock) != 0) {
        fprintf(stderr, "ERROR: close(socked) failed!\n");
        exit(1);
    }
    exported_flows_cnt++;
}

/**
 * Export all flows from flow-cache to collector
 */
void export_full_flows_cache() {
    std::map<tuple<std::string, std::string, short unsigned int, short unsigned int, std::string, int>, One_flow_params>::iterator it;
    std::tuple<std::string, std::string, short unsigned int, short unsigned int, std::string, int> mapKey;

    // iterate through all stored flows in map
    while (!map_of_all_flows.empty()) {
        it = map_of_all_flows.begin();
        mapKey = it->first;
        One_flow_params OneFlowParams = it->second;

        // add flow to export
        export_flow(&OneFlowParams);
        it = map_of_all_flows.find(mapKey);
        map_of_all_flows.erase(it--);
    }
}
