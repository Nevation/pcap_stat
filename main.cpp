#include <stdio.h>
#include <pcap.h>
#include <vector>
#include <map>
#include <set>
#include <iostream>
using namespace std;

#define KB 1024
#define MB (1024 * 1024)
#define GB (1024 * 1024 * 1024)

void usage() {
	printf("syntax: pcap_stat <pcap file name>\n");
	printf("sample: pcap_stat data.pcap\n");
}

struct EndpointData {
	int dst_count = 0;
	int dst_size = 0;

	int src_count = 0;
	int src_size = 0;
};

string get_calc_size(int size){
	string result = to_string(size);

	if (size > GB) 		{ result = to_string(size/GB) + "." + to_string(size/(GB/10))[1] + "G"; }
	else if (size > MB)	{ result = to_string(size/MB) + "." + to_string(size/(MB/10))[1] + "M"; }
	else if (size > KB)	{ result = to_string(size/KB) + "." + to_string(size/(KB/10))[1] + "K"; }

	return result;
}

int get_size(const u_char* len){
	return len[0] * 16 + len[1];
}

int main(int argc, char* argv[]){
	if (argc != 2) {
		usage();
		return -1;
	}

	char* pcap_file = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_offline(pcap_file, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "couldn't open file %s: %s\n", pcap_file, errbuf);
		return -1;
	}

	map<pair<vector<u_char>, vector<u_char>>, EndpointData> packet_map;
	set<pair<vector<u_char>, vector<u_char>>> key;

	while (true){        
		struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
    
        pair<vector<u_char>, vector<u_char>> dst_endpoint;
        pair<vector<u_char>, vector<u_char>> src_endpoint;

        vector<u_char> dst_mac(packet, packet + 6);
        vector<u_char> dst_ip_addr(&packet[30], &packet[30] + 4);
        
        vector<u_char> src_mac(&packet[6], &packet[6] + 6);
        vector<u_char> src_ip_addr(&packet[26], &packet[26] + 4);
        

        dst_endpoint = make_pair(dst_mac, dst_ip_addr);
        src_endpoint = make_pair(src_mac, src_ip_addr);

        key.insert(dst_endpoint);
        key.insert(src_endpoint);

        int size = get_size(&packet[16]);

        packet_map[dst_endpoint].dst_count ++;
        packet_map[dst_endpoint].dst_size += size;

        packet_map[src_endpoint].src_count ++;
        packet_map[src_endpoint].src_size += size;
    }

	pcap_close(handle);
    printf("Mac\t\t\t\t\tAddress\t\t\tPacket\t\tBytes\t\tTx Packets\tTx Bytes\tRx Packets\tRx Bytes\n");

    for (auto k: key){
    	for (auto i: k.first){
    		printf("%02x ", i);
    	} printf("\t");
    	
    	for (auto i: k.second){
    		printf("%02x ", i);
    	} printf("\t");

    	printf("%-12d%-12s", packet_map[k].dst_count + packet_map[k].src_count,
    						get_calc_size(packet_map[k].dst_size + packet_map[k].src_size).c_str());
    	printf("%-12d%-12s", packet_map[k].dst_count, get_calc_size(packet_map[k].dst_size).c_str());
    	printf("%-12d%-12s", packet_map[k].src_count, get_calc_size(packet_map[k].src_size).c_str());
    	printf("\n");
    }

	return 0;
}