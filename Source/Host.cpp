#include "Host.h"

Host::Host(ip_address l_ip_address,const unsigned char * l_ether_addr) {
	m_portList = new std::map<int, std::string,std::greater<int>>; //New PortList we set an algorithm for sorting the ports the lowest to the higgest
	m_Ip_Addr = l_ip_address; //New ip address
	memcpy(m_etherAddr, l_ether_addr, ETHER_ADDR_LEN); //Copy the MAC address inserted in arguments to the m_etherAddr
}
Host::~Host(){
	m_portList->clear();

}
std::map<int, std::string,std::greater<int>>* Host::GetPortList() {
return m_portList;
}
ip_address Host::GetIpAddress() {
	return m_Ip_Addr;
}
void Host::SetIPAddr(ip_address& ip_addr) {
	m_Ip_Addr = ip_addr;
}
const unsigned char *Host::GetMACAddr() {
	return m_etherAddr;
}
/*The function return an boolean so as to know if
 *We found a new port that hasn't been included yet in this Host
 * Or if the port that we found was already found before...
*/
bool Host::AddNewPort(short l_port,ExistingPort* l_existport) {
	/*Verify if it exists in l_existports if not the value is equal to "TCP"*/
	std::string portName = "Name of the port";
	std::unordered_map<int, std::string>::iterator itExistingPort;
	itExistingPort = l_existport->AllPortsNumber.find(l_port);
	if (itExistingPort == l_existport->AllPortsNumber.end()) {
		portName = "TCP";
	}
	/*Does this port is already inserted in our map?*/
	std::map<int, std::string>::iterator itHostPort;
	itHostPort = m_portList->find(l_port);
	if (itHostPort == m_portList->end())/*If this element doesn't exist we can insert it*/
	{
		if (portName != "TCP")
			portName = l_existport->AllPortsNumber.at(l_port); /*It mean we found one of the famous service included in l_existport*/
		m_portList->insert(std::pair<int, std::string>(l_port, portName));
		return true;
	}
	else { /*This port already exist so we can't add it again*/
		return false;
	}
}
void Host::DisplayHost(Host& l_host) {
	printf("%d.%d.%d.%d {\r\n", l_host.m_Ip_Addr.byte1, l_host.m_Ip_Addr.byte2, l_host.m_Ip_Addr.byte3, l_host.m_Ip_Addr.byte4); //Display each bytes of an ip address in a readable format
	for (auto const& PortIt : *m_portList) { //And then display each port that we found about the host
		std::cout <<"\t" << PortIt.first << ":" << PortIt.second << std::endl;
	}
	std::cout << "}\r\n";

}