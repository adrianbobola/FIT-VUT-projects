/*
 * FIT VUT - ISA 2023 - Monitorování DHCP komunikace
  @author Adrián Bobola (xbobol00)
 */
#include <iostream>
#include <cstring>
#include <regex>
#include <complex>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <ncurses.h>
#include <syslog.h>

using namespace std;
#define FAVOR_BSD

void parse_params(int argc, char** argv);

void parse_packet(u_char* args, const pcap_pkthdr* packet_header, const u_char* packet);

double calculate_max_hosts(int prefix);

void print_statistics();

struct given_params {
    string file_name;
    string interface_name;
} params;

struct ip_prefix_details {
    unsigned long ip;
    u_int16_t prefix;
    long int hosts = 0;
    int allocated = 0;
    double utilization = 0;
    bool syslog_exported = false;
};

struct dhcp_message {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    char chaddr[16];
    char sname[64];
    char file[128];
    char options[256];
};

pcap_t* packet;
std::vector<ip_prefix_details> all_ip_prefixes;
std::vector<u_int32_t> processed_packets;
bool file_name_flag = false;
bool interface_name_flag = false;

int main(int argc, char** argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_program bpf_program{};

    parse_params(argc, argv);

    // ncurses init
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, FALSE);
    move(0, 0);
    printw("IP-Prefix Max-hosts Allocated addresses Utilization\n");
    for (auto&all_ip_prefixes_print: all_ip_prefixes) {
        const uint32_t hex_ip = htonl(all_ip_prefixes_print.ip);
        printw("%d.%d.%d.%d/%d %ld %u %.2f%%\n",
               ((hex_ip >> 24) & 0xFF), ((hex_ip >> 16) & 0xFF), ((hex_ip >> 8) & 0xFF),
               ((hex_ip & 0xFF)),
               all_ip_prefixes_print.prefix,
               all_ip_prefixes_print.hosts,
               all_ip_prefixes_print.allocated,
               all_ip_prefixes_print.utilization);
    }
    refresh();

    if (file_name_flag) {
        // open pcap file
        packet = pcap_open_offline(params.file_name.c_str(), errbuf);
        if (packet == nullptr) {
            endwin();
            fprintf(stderr, "Error packet open - pcap_open_offline\n");
            exit(1);
        }
    }
    else {
        // open live data from interface name, promiscuous mode off
        packet = pcap_open_live(params.interface_name.c_str(), BUFSIZ, 0, 1000, errbuf);
        if (packet == nullptr) {
            endwin();
            fprintf(stderr, "Error packet open - pcap_open_live\n");
            exit(1);
        }
    }

    // pcap_setfilter to UDP and ACK only
    char filter_exp[] = "udp port 67";

    // compile filter
    if (pcap_compile(packet, &bpf_program, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        endwin();
        fprintf(stderr, "Error pcap filter compile - pcap_compile\n");
        exit(1);
    }

    // set filter
    if (pcap_setfilter(packet, &bpf_program) == -1) {
        endwin();
        fprintf(stderr, "Error pcap set filter - pcap_setfilter\n");
        exit(1);
    }

    // pcap_loop
    if (pcap_loop(packet, 0, parse_packet, nullptr) < 0) {
        endwin();
        fprintf(stderr, "Error - pcap_loop\n");
        exit(1);
    }

    pcap_close(packet);

    // close ncurses window
    getch();
    endwin();
    return 0;
}

/**
 * Parsing arguments from argv
 * @param argc
 * @param argv
 */
void parse_params(int argc, char** argv) {
    int opt;
    while ((opt = getopt(argc, argv, "r:i:")) != -1) {
        switch (opt) {
            case 'r': {
                params.file_name = optarg;
                file_name_flag = true;
                break;
            }
            case 'i': {
                params.interface_name = optarg;
                interface_name_flag = true;
                break;
            }
            default:
                endwin();
                fprintf(stderr, "ERROR: Unknow option: \"%c\"\n", optopt);
                exit(1);
        }
    }

    // multiple options were given
    if (file_name_flag and interface_name_flag) {
        endwin();
        fprintf(stderr, "ERROR: Nepovolena kombinace prepinacu -r a -i \n");
        exit(1);
    }

    // no options were given
    if (!file_name_flag and !interface_name_flag) {
        endwin();
        fprintf(stderr, "ERROR: Nepouzity jeden z prepinacu -r nebo -i \n");
        exit(1);
    }

    // processing others options
    for (int i = optind; i < argc; i++) {
        std::vector<char *> splitted_ip_prefix = {};

        // convert input string to IP and prefix
        char* helper = strtok(argv[i], "/");
        splitted_ip_prefix.push_back(helper);
        while (helper != nullptr) {
            helper = strtok(nullptr, "/");
            splitted_ip_prefix.push_back(helper);
        }

        // check if split "IP/Prefix" to "IP" and "prefix" works
        if (splitted_ip_prefix.size() != 3) {
            endwin();
            fprintf(stderr, "ERROR: Invalid IP address\n");
            exit(1);
        }

        // validate IP
        const unsigned long ipv4_inet = inet_addr(splitted_ip_prefix[0]);
        if (ipv4_inet == INADDR_NONE) {
            endwin();
            fprintf(stderr, "ERROR: Invalid IP address\n");
            exit(1);
        }

        // validate prefix
        char* endptr;
        const u_int16_t prefix = strtol(splitted_ip_prefix[1], &endptr, 10);
        if (*endptr != '\0') {
            endwin();
            fprintf(stderr, "ERROR: Conversion failed. Subnet is not a valid integer\n");
            exit(1);
        }

        if (prefix < 0 || prefix > 32) {
            endwin();
            fprintf(stderr, "ERROR: Invalid IP address\n");
            exit(1);
        }

        // save IP-Prefix information
        ip_prefix_details new_IP{};
        new_IP.ip = ipv4_inet;
        new_IP.prefix = prefix;
        new_IP.hosts = (long int)calculate_max_hosts(prefix);
        all_ip_prefixes.push_back(new_IP);
    }
}

/**
 * Parsing packet
 * @param args
 * @param packet_header
 * @param packet
 */
void parse_packet(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet) {
    auto* dhcp = (struct dhcp_message *)
            (packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

    // iterate through all packet options
    for (std::size_t i = 0; i < sizeof(dhcp->options); i++) {
        // check DHCP option 53 (RFC2132) - DHCP Message Type
        if (dhcp->options[i] == 53) {
            // check value 5 (RFC2132) - DHCPACK
            if (dhcp->options[i + 2] == 5) {
                // check if packet yiaddr is not 0.0.0.0
                if (dhcp->yiaddr != 0) {
                    // try to find a IP in already processed_packets
                    auto it = std::find(processed_packets.begin(),
                                        processed_packets.end(), dhcp->yiaddr);

                    if (it == processed_packets.end()) {
                        // given packet IP is new and I dont have it, add to statistics
                        processed_packets.push_back(dhcp->yiaddr);
                        print_statistics();
                    }
                }
            }
        }
    }
}

/**
 * Calculate max hosts for given prefix number
 * @param prefix - prefix number
 */
double calculate_max_hosts(const int prefix) {
    if (prefix == 32) {
        return 0;
    }
    const int max_prefix_bits = 32;
    const int hosts_bits = max_prefix_bits - prefix;
    double possible_IP_cnt = std::pow(2, hosts_bits);

    // subtract network and broadcast address
    possible_IP_cnt -= 2;
    return possible_IP_cnt;
}

/**
 * Computing new statistics for all given IP-prefixes and write it to app window
 */
void print_statistics() {
    for (auto&all_ip_prefix: all_ip_prefixes) {
        // reset old statistics before computing new
        all_ip_prefix.allocated = 0;
        all_ip_prefix.utilization = 0;

        // compute subnet mask in hex for given prefix number
        unsigned long subnet_mask = 0;
        if (all_ip_prefix.prefix != 0) {
            subnet_mask = 0xFFFFFFFFF << (32 - all_ip_prefix.prefix);
        }

        // convert IP address to hex for apply subnet_mask
        const uint32_t hex_IP = htonl(all_ip_prefix.ip);
        const uint32_t broadcast_address = hex_IP | ~subnet_mask;
        const uint32_t network_address = hex_IP & subnet_mask;

        for (auto&actual_processed_packets: processed_packets) {
            const uint32_t hex_IP_actual_processing_packet = htonl(actual_processed_packets);

            // check if actual processing "packet IP" belong to actual processing "given IP and subnet"
            if ((hex_IP_actual_processing_packet & subnet_mask) == (hex_IP & subnet_mask)) {
                // acheck if ctual processing "packet IP" is not a boradcast or network
                if (hex_IP_actual_processing_packet != broadcast_address &&
                    hex_IP_actual_processing_packet != network_address) {
                    all_ip_prefix.allocated += 1;
                    // preventing segfault when dividing by zero in prefixes that not exists
                    if ((all_ip_prefix.allocated != 0) && (all_ip_prefix.hosts == 0)) {
                        all_ip_prefix.hosts = 1;
                    }
                    all_ip_prefix.utilization = ((double)all_ip_prefix.allocated /
                                                 (double)all_ip_prefix.hosts) * 100;
                }
            }
        }

        // statistics has changed, update window
        move(0, 0);
        printw("IP-Prefix Max-hosts Allocated addresses Utilization\n");
        for (auto&all_ip_prefix_print: all_ip_prefixes) {
            const uint32_t hex_ip = htonl(all_ip_prefix_print.ip);
            printw("%d.%d.%d.%d/%d %ld %u %.2f%%\n",
                   ((hex_ip >> 24) & 0xFF), ((hex_ip >> 16) & 0xFF), ((hex_ip >> 8) & 0xFF),
                   ((hex_ip & 0xFF)),
                   all_ip_prefix_print.prefix,
                   all_ip_prefix_print.hosts,
                   all_ip_prefix_print.allocated,
                   all_ip_prefix_print.utilization);
        }

        // check utilization value for syslog notice
        if ((all_ip_prefix.utilization > 50.00) && (all_ip_prefix.syslog_exported == false)) {
            setlogmask(LOG_UPTO(LOG_NOTICE));
            openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

            syslog(LOG_NOTICE, "prefix %d.%d.%d.%d/%d exceeded 50%% of allocations.",
                   ((hex_IP >> 24) & 0xFF), ((hex_IP >> 16) & 0xFF), ((hex_IP >> 8) & 0xFF),
                   ((hex_IP & 0xFF)), all_ip_prefix.prefix);
            printw("prefix %d.%d.%d.%d/%d exceeded 50%% of allocations.",
                   ((hex_IP >> 24) & 0xFF), ((hex_IP >> 16) & 0xFF), ((hex_IP >> 8) & 0xFF),
                   ((hex_IP & 0xFF)), all_ip_prefix.prefix);
            // set as already exported for disabling syslong spamming
            all_ip_prefix.syslog_exported = true;
        }
        refresh();
    }
}

