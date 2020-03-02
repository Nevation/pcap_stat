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

	map<pair<vector<u_char>, vector<u_char>>, EndpointData> endpoints;
	set<pair<vector<u_char>, vector<u_char>>> endpoint_key;

    map<pair<vector<u_char>, vector<u_char>>, EndpointData> conversations;
    set<pair<vector<u_char>, vector<u_char>>> conversation_key;

	while (true){        
		struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
    
        pair<vector<u_char>, vector<u_char>> dst_endpoint;
        pair<vector<u_char>, vector<u_char>> src_endpoint;
        pair<vector<u_char>, vector<u_char>> addr_to_addr;

        vector<u_char> dst_mac(packet, packet + 6);
        vector<u_char> dst_ip_addr(&packet[30], &packet[30] + 4);
        
        vector<u_char> src_mac(&packet[6], &packet[6] + 6);
        vector<u_char> src_ip_addr(&packet[26], &packet[26] + 4);
        

        dst_endpoint = make_pair(dst_mac, dst_ip_addr);
        src_endpoint = make_pair(src_mac, src_ip_addr);
        addr_to_addr = make_pair(dst_mac, src_mac);

        endpoint_key.insert(dst_endpoint);
        endpoint_key.insert(src_endpoint);

        int size = get_size(&packet[16]);

        endpoints[dst_endpoint].dst_count ++;
        endpoints[dst_endpoint].dst_size += size;

        endpoints[src_endpoint].src_count ++;
        endpoints[src_endpoint].src_size += size;

        auto back = make_pair(src_mac, dst_mac);
        if (conversation_key.count(back) == 1){
            conversations[back].src_count++;
            conversations[back].src_size += size;
        } else {
            conversations[addr_to_addr].dst_count++;
            conversations[addr_to_addr].dst_size += size;
            conversation_key.insert(addr_to_addr);
        }
    }

	pcap_close(handle);

    printf("Endpoints\n");
    printf("Mac\t\t\tAddress\t\tPacket\t    Bytes\tTx Packets  Tx Bytes\tRx Packets  Rx Bytes\n");

    for (auto endpoint: endpoint_key){
    	for (auto mac: endpoint.first){
    		printf("%02x ", mac);
    	} printf("\t");
    	
    	for (auto ip_addr: endpoint.second){
    		printf("%02x ", ip_addr);
    	} printf("\t");

        auto endp = endpoints[endpoint];

    	printf("%-12d%-12s", endp.dst_count + endp.src_count, get_calc_size(endp.dst_size + endp.src_size).c_str());
    	printf("%-12d%-12s", endp.dst_count, get_calc_size(endp.dst_size).c_str());
    	printf("%-12d%-12s", endp.src_count, get_calc_size(endp.src_size).c_str());
    	printf("\n");
    }


    printf("\n\nConversations\n");
    printf("Address A\t\tAddress B\t\tPacket\t    Bytes\tTx Packets  Tx Bytes\tRx Packets  Rx Bytes\n");


    for(auto conversation: conversation_key){
        for (auto addr_a: conversation.first) {
            printf("%02x ", addr_a);
        } printf("\t");

        for (auto addr_b: conversation.second) {
            printf("%02x ", addr_b);
        } printf("\t");
        

        auto conv = conversations[conversation];
        printf("%-12d%-12s", conv.dst_count + conv.src_count, get_calc_size(conv.dst_size + conv.src_size).c_str());
        printf("%-12d%-12s", conv.dst_count, get_calc_size(conv.dst_size).c_str());
        printf("%-12d%-12s", conv.src_count, get_calc_size(conv.src_size).c_str());
        printf("\n");    
    }
	return 0;
}