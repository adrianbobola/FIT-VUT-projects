/*
 * FIT VUT - ISA 2022 - Generovani NetFlow dat ze zachycene sitove komunikace
  @author Adrián Bobola (xbobol00)
 */

#include <iostream>

/**
 * Struct for saving flow params before export it - Flow v5
 */
struct flow_v5_export {
    u_int16_t version;
    u_int16_t count;
    u_int32_t sysUptime;
    u_int32_t unix_secs;
    u_int32_t unix_nsecs;
    u_int32_t flow_sequence;
    u_int8_t engine_type;
    u_int8_t engine_id;
    u_int16_t sampling_interval;
    u_int32_t srcaddr;
    u_int32_t dstaddr;
    u_int32_t nexthop;
    u_int16_t input;
    u_int16_t output;
    u_int32_t dPkts;
    u_int32_t dOctets;
    u_int32_t First;
    u_int32_t Last;
    u_int16_t srcport;
    u_int16_t dstport;
    u_int8_t pad1;
    u_int8_t tcp_flags;
    u_int8_t prot;
    u_int8_t tos;
    u_int16_t src_as;
    u_int16_t dst_as;
    u_int8_t src_mask;
    u_int8_t dst_mask;
    u_int16_t pad2;
};

/**
 * Struct for saving command line arguments
 */
struct run_params {
    std::string file_name;
    std::string ip;
    std::string port;
    unsigned active_timer;
    unsigned inactive_timer;
    unsigned flow_cache_size;
};

/**
 * Storing all params for one flow
 */
struct One_flow_params {
    u_int32_t srcIp;
    u_int32_t destIp;
    uint16_t srcPort;
    uint16_t destPort;
    uint8_t prot;
    uint8_t tos;
    timeval First;
    timeval Last;
    u_int32_t dPkts;
    uint32_t dOctets;
    u_int8_t tcp_flags;
};

/**
 * Saving timestamp in timeval format
 */
struct timeval actual_time{};

/**
 * Parsing command-line options
 * @param argc - argument count
 * @param argv - argument vector
 */
void params_parser(int argc, char **argv);

/**
 * Parsing one packet - function called from pcap_loop
 * @param args - Non-Keyword Arguments
 * @param header - packet header
 * @param packet - packet
 */
void packet_parser(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/**
 * Checking First and Last timer for every stored flow.
 *  If flow stored time is more than active or inactive timer, then delete it from flow cache
 * @param actualFlowTime - actual packet time in timeval struct
 */
void check_timers(timeval actualFlowTime);

/**
 * Checking number of Flows stored in cache
 *  If nb. of stored flows is more than -m param, then export first item from map
 */
void check_cache_size();

/**
 * Send one flow to collector via UDP
 * @param OneFlowParams - One_flow_params struct from sending flow
 */
void export_flow(One_flow_params *OneFlowParams);

/**
 * Export all flows from flow-cache to collector
 */
void export_full_flows_cache();