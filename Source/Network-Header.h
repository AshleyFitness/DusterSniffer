/*SPECIAL NOTES!!
 THE WINDOWS OS ALWAYS USE LITTLE-ENDIAN ARCHITECTURE!
 WE DONT NEED TO SEARCH WHICH TYPE OF ARCHITECTURE WE ARE USING
 (except if i want to export this project for the Linux OS)

 This header file defines  few Protcole Header that will be very useful 
 For decrypting data
 We defines the current header : ETHERNET_HEADER,IP_HEADER,UDP_HEADER,TCP_HEADER

Some function are defined as well which allow us to decrypt data in a readable way

*/

#pragma once

#ifndef NETWORK_HEADER_H
#define NETWORK_HEADER_H
#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <unordered_map>
#define ETHER_ADDR_LEN 6 //Length of an MAC address
#define ETHER_HDR_LEN 14 //Length of an ETHERNET Header
struct ip_address { /*We use an structure of 4 bytes that allows us to avoid the usage of inet_ntoa() which is unsecured*/
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	bool operator==(ip_address const& ip_addrB) //Function to compare 2 ip address
	{
		if (byte1 == ip_addrB.byte1 && byte2 == ip_addrB.byte2 && byte3 == ip_addrB.byte3 && byte4 == ip_addrB.byte4) //If all Bytes are equal return true 
			return true;
		else
			return false;
	}
};

struct ether_hdr {
	unsigned char ether_dest_addr[ETHER_ADDR_LEN]; //Mac Destination Adress 
	unsigned char ether_src_addr[ETHER_ADDR_LEN];  //Mac Sources Address
	unsigned short ether_type; //Type of ethernet packet
};

#define IP_HDR_LEN 20
struct ip_hdr {
	unsigned char ip_version_and_header_length; //Version and header length.
	unsigned char ip_tos; //Type of service
	unsigned short ip_len; //Totale length
	unsigned short ip_id; //Id of the ip
	unsigned short ip_frag_offset; //Fragment offset
	unsigned char ip_ttl; //Time to live.
	unsigned char ip_type; //Type of protocole
	unsigned short ip_checksum; //Header checksum
	struct ip_address ip_src_addr; //IP Source  address
	struct ip_address ip_dest_addr; //IP Destination  address
};
#define UDP_HDR_LEN 8
struct udp_hdr {
	unsigned short src_port; //Source port
	unsigned short dest_port;//destination port
	unsigned short len; //datagram length
	unsigned short checksum; //Checksum
};
#define TCP_HDR_LEN 20
struct tcp_hdr {
	unsigned short tcp_src_port; //TCP source port
	unsigned short tcp_dest_port; //TCP destination port
	unsigned int tcp_seq; // TCP Sequence Number 
	unsigned int tcp_ack; // TCP Acknowledgment number
	unsigned char reserved : 4; //4 reserved bits
	unsigned char tcp_offset : 4; //TCP Data offset for little-endian
	unsigned char tcp_flags; //TCP Indicator (and 2 bits reserved).
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
	unsigned short tcp_window; //Size of the TCP window
	unsigned short tcp_checksum; //Checksum of TCP
	unsigned short tcp_urgent; //TCP Urgent pointer
};




/*IPV6 Header isn't supported yet.... :/*/

/*All the decoding functions...*/
//This function decode the ETHERNET Header (Inspired from Hacking: The Art of Exploitation 2nd edition)
inline void decode_ethernet(const u_char* header_start) {
	int i; //Used to loop through MAC address bytes
	const struct ether_hdr* ethernet_header; //Handle to our ethernet header

	ethernet_header = (const struct ether_hdr*)header_start; //We set the ethernet_header where the ethernet header is located on the packet
	std::cout << "[[ Layer 2 :: Ethernet Header ]]\n"; //Display the source ETHERNET address
	printf("[ Source : %02x", ethernet_header->ether_src_addr[0]); 
	for (i = 1; i < ETHER_ADDR_LEN; i++)
		printf(":%02x", ethernet_header->ether_src_addr[i]);

	printf("\tDestination: %02x", ethernet_header->ether_dest_addr[0]); //Display the Destination ETHERNET address
	for (i = 1; i < ETHER_ADDR_LEN; i++)
		printf(":%02x", ethernet_header->ether_src_addr[i]);
	printf("\tType: %hu ]\n", ethernet_header->ether_type); //Display the Type
}
inline void decode_ip(const u_char* header_start) {
	const struct ip_hdr* ip_header; //An handle to the ip header located on the packet
	ip_header = (const struct ip_hdr*)header_start; //We set the ip_header where the ip header is located on the packet

	std::cout << "\t(( Layer 3 ::: IP Header ))\n";
	printf("\t(Source: %d.%d.%d.%d\t", ip_header->ip_src_addr.byte1, ip_header->ip_src_addr.byte2, ip_header->ip_src_addr.byte3, ip_header->ip_src_addr.byte4); //Display source ip address
	printf("Destination: %d.%d.%d.%d\n", ip_header->ip_dest_addr.byte1, ip_header->ip_dest_addr.byte2, ip_header->ip_dest_addr.byte3, ip_header->ip_dest_addr.byte4); //Display Destination ip address
	printf("\t( Type: %u\t", (u_int)ip_header->ip_type); //Display IP Type
	printf("ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len)); //Display the IP Id and the Length

}
//A simple function that display the Source IP
inline void display_ip_addressSrc(const u_char* header_start) {
	const struct ip_hdr* ip_header;
	ip_header = (const struct ip_hdr*)header_start;
	printf("Source : %d.%d.%d.%d", ip_header->ip_src_addr.byte1, ip_header->ip_src_addr.byte2, ip_header->ip_src_addr.byte3, ip_header->ip_src_addr.byte4);
}
//An simple function that display the Destination IP
inline void display_ip_addressDest(const u_char* header_start) {
	const struct ip_hdr* ip_header;
	ip_header = (const struct ip_hdr*)header_start;
	printf("Destination : %d.%d.%d.%d", ip_header->ip_dest_addr.byte1, ip_header->ip_dest_addr.byte2, ip_header->ip_dest_addr.byte3, ip_header->ip_dest_addr.byte4);
}
//This Function display each connection on the network that use the UDP protocol
inline void decode_udp(const u_char * ip_header_start,const u_char* udp_header_start) {
	udp_hdr* udp_header = (udp_hdr*)udp_header_start;
	u_short sport, dport;
	sport = ntohs(udp_header->src_port); //Convert to the host byte order
	dport = ntohs(udp_header->dest_port);
	display_ip_addressSrc(ip_header_start); //Display the source ip address 
	std::cout << ":" << sport << " -> ";
	display_ip_addressDest(ip_header_start); //Display the destination ip address
	std::cout << ":" << dport << std::endl;
}
inline u_int decode_tcp(const u_char* header_start) {
	u_int header_size;
	const struct tcp_hdr* tcp_header;

	tcp_header = (const struct tcp_hdr*)header_start;
	header_size = 4 * tcp_header->tcp_offset; //calculate the header size

	printf("\t\t{{ Layer 4 :::: TCP header }}\n");
	printf("\t\t{Source Port: %hu\t", ntohs(tcp_header->tcp_src_port));//Display the source port
	printf("Destination Port: %hu }\n", ntohs(tcp_header->tcp_dest_port)); //Display the destination port
	printf("\t\t{ Seq #: %u\t", ntohl(tcp_header->tcp_seq)); //Display the Sequence number
	printf("Ack #: %u }\n", ntohl(tcp_header->tcp_ack)); //Display the ACK number
	printf("\t\t{ TCP Header Length: %u\tFlag: ", header_size); //Display the header size

	//If there is any flag in the packet display them
	if (tcp_header->tcp_flags & TCP_FIN) 
		printf("FIN ");
	if (tcp_header->tcp_flags & TCP_SYN)
		printf("SYN ");
	if (tcp_header->tcp_flags & TCP_RST)
		printf("RST ");
	if (tcp_header->tcp_flags & TCP_PUSH)
		printf("PUSH ");
	if (tcp_header->tcp_flags & TCP_ACK)
		printf("ACK ");
	if (tcp_header->tcp_flags & TCP_URG)
		printf("URG ");
	printf(" }\n");

	return header_size; //and we return the header size
}
/*This function will return the locale ip address of an IP header*/
inline ip_address GetIpAddrFromPckt(const u_char* header_start) {
	const struct ip_hdr* ip_header;
	ip_header = (const struct ip_hdr*)header_start;
	return ip_header->ip_src_addr;
}
//this function return the src port number from an packet
inline unsigned short GetPortFromPckt(const u_char* header_start) {
	const struct tcp_hdr* tcp_header;
	tcp_header = (const struct tcp_hdr*)header_start;
	return ntohs(tcp_header->tcp_src_port);
}
//this function return the Src MAC ADDRESS from an packet
inline const unsigned char* GetEtherSrcAddr(const u_char* header_start) {
	const struct ether_hdr *ether_header;
	ether_header = (const struct ether_hdr*)header_start;
	return ether_header->ether_src_addr;
}


//Same but for destination
inline ip_address GetDestIpAddrFromPckt(const u_char* header_start) {
	const struct ip_hdr* ip_header;
	ip_header = (const struct ip_hdr*)header_start;
	return ip_header->ip_dest_addr;
}

inline unsigned short GetDestPortFromPckt(const u_char* header_start) {
	const struct tcp_hdr* tcp_header;
	tcp_header = (const struct tcp_hdr*)header_start;


	return ntohs(tcp_header->tcp_dest_port);
}
inline const unsigned char* GetDestEtherAddr(const u_char* header_start) {
	const struct ether_hdr* ether_header;
	ether_header = (const struct ether_hdr*)header_start;
	return ether_header->ether_dest_addr;
}
/*This little part will defines some Famous PORT (all PORTS that exist in the universe isn't included here)
I just included the most famous one!
This function is pretty useful to get information like for example if there is a web server in your network
or an FTP server and much more 
This list was based from : https://web.mit.edu/rhel-doc/4/RH-DOCS/rhel-sg-en-4/ch-ports.html
Feel free to increase this list (because there is not a lot of port here)

(This function is used in ExistingPort structure)
*/

inline std::unordered_map<int,std::string> 
InitPortNumber(){
	std::unordered_map<int ,std::string> portList;
	portList[1] = "tcpmux";
	portList[5] = "rje";
	portList[7] = "echo";
	portList[9] = "discard";
	portList[11] = "systat";
	portList[13] = "daytime";
	portList[17] = "qotd";
	portList[18] = "msp";
	portList[19] = "chargen";
	portList[20] = "ftp-data";
	portList[21] = "ftp";
	portList[22] = "ssh";
	portList[23] = "telnet";
	portList[25] = "smtp";
	portList[37] = "time";
	portList[39] = "rlp";
	portList[42] = "nameserver";
	portList[43] = "nicname";
	portList[49] = "tacacs";
	portList[50] = "re-mail-ck";
	portList[53] = "DNS";
	portList[63] = "whois++";
	portList[67] = "bootps";
	portList[68] = "bootpc";
	portList[69] = "tftp";
	portList[70] = "gopher";
	portList[71] = "netjrs-1";
	portList[72] = "netjrs-2";
	portList[73] = "netjrs-3 or netjrs-4";
	portList[79] = "finger";
	portList[80] = "http";
	portList[88] = "kerberos";
	portList[95] = "supdup";
	portList[101] = "hostname";
	portList[102] = "iso-tsap";
	portList[105] = "csnet-ns";
	portList[107] = "rtelnet";
	portList[109] = "pop2";
	portList[110] = "pop3";
	portList[111] = "sunrpc";
	portList[113] = "auth";
	portList[115] = "sftp";
	portList[117] = "uucp-path";
	portList[119] = "nntp";
	portList[123] = "ntp";
	portList[137] = "netbios-ns";
	portList[138] = "netbios-dgm";
	portList[139] = "netbios-ssn";
	portList[143] = "imap";
	portList[161] = "snmp";
	portList[162] = "snmptrap";
	portList[163] = "cmip-man";
	portList[164] = "cmip-agent";
	portList[174] = "mailq";
	portList[177] = "xdmcp";
	portList[178] = "nextstep";
	portList[179] = "bgp";
	portList[191] = "prospero";
	portList[194] = "irc";
	portList[199] = "smux";
	portList[201] = "at-rtmp";
	portList[202] = "at-nbp";
	portList[204] = "at-echo";
	portList[206] = "at-zis";
	portList[209] = "qmtp";
	portList[210] = "z39.50";
	portList[213] = "imap3";
	portList[245] = "link";
	portList[347] = "fatserv";
	portList[363] = "rsvp_tunnel";
	portList[369] = "rpc2portmap";
	portList[370] = "codaauth2";
	portList[372] = "ulistproc";
	portList[389] = "ldap";
	portList[427] = "svrloc";
	portList[434] = "mobileip-agent";
	portList[435] = "mobilip-mn";
	portList[443] = "https";
	portList[444] = "snpp";
	portList[445] = "microsoft-ds";
	portList[464] = "kpasswd";
	portList[468] = "photuris";
	portList[487] = "saft";
	portList[488] = "gss-http";
	portList[496] = "pim-rp-disc";
	portList[500] = "isakmp";
	portList[535] = "iiop";
	portList[538] = "gdomap";
	portList[546] = "dhcpv6-client";
	portList[547] = "dhcpv6-server";
	portList[554] = "rtsp";
	portList[563] = "nntps";
	portList[565] = "whoami";
	portList[587] = "submission";
	portList[610] = "npmp-local";
	portList[611] = "npmp-gui";
	portList[612] = "hmmp-ind";
	portList[631] = "ipp";
	portList[636] = "Idaps";
	portList[674] = "acap";
	portList[694] = "ha-cluster";
	portList[749] = "kerberos-adm";
	portList[750] = "kerberos-iv";
	portList[767] = "phonebook";
	portList[873] = "rsync";
	portList[992] = "telnets";
	portList[993] = "imaps";
	portList[994] = "ircs";
	portList[995] = "pop3s";
	return portList; //return the entire list we just created
}
#endif