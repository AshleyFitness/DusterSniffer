#pragma once
/*This header files defines an class used for the Get Ip Addresses and PORT
We will put a bunch of method and we will contais a lot of datastructure inside
that will contain our IP addresses,PORT and much more
*/
#ifndef HOST_H
#define HOST_H
#include "Network-Header.h"
#include <map>
struct ExistingPort { //This data structure is simply an Initialised std::unordered_map with famous protocol name like HTTP,FTP,TELNET,SSH
	std::unordered_map<int, std::string> AllPortsNumber;
	ExistingPort() { //When created initialise the map with all famous port name and numbers
		AllPortsNumber = InitPortNumber(); 
	}
};/*This simple structure will be used
  to compare the portList of an Host and all the ports number we defined in InitPortNumber() (check Network-Header.h to see all the ports we had defined)
  */

class Host {
public:
	Host(ip_address l_ip_addr,const unsigned char * l_ether_addr); /*Constructor*/
	~Host(); //Destructor
	std::map<int,std::string,std::greater<int>>* GetPortList(); //We will return m_portList
	ip_address GetIpAddress(); //We will return m_Ip_Addr
	bool AddNewPort(short l_port,ExistingPort* l_existport); //We found an new port! Add it to the portList
	void SetIPAddr(ip_address& ip_addr); //Set the IP address of the host
	void DisplayHost(Host& l_host); //Display the current host on the console
	const unsigned char * GetMACAddr(); //Get the MAC Address
private:
	std::map<int, std::string,std::greater<int>>* m_portList; //All the ports opened of the host
	ip_address m_Ip_Addr; //the ip address of the host
	u_char m_etherAddr[ETHER_ADDR_LEN]; //The MAC Address of the host
};
#endif
