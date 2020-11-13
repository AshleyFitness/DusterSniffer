
#pragma once
#ifndef SNIFFER_H
#define SNIFFER_H
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <string>
#include <ctime>
#include <algorithm>
#include <csignal>
#include <fstream>
#include <chrono>
#include "ErrorHandler.h"
#include "SigContainer.h"
#include "Host.h"
/*MAIN CLASS OF THE WHOLE PROGRAM
  ALMOST ALL THE PROGRAM IS BASED ON THIS CLASS
  IT'S AN COMPLEX CLASS THAT IS AN SNIFFER THAT ALLOW US MULTIPLE POSSIBILITIES
  WE CAN SNIFF UDP PACKETS,TCP AND MUCH MORE
*/


/*We cant use those function inside our class, pcap_loop() only accept vanilla function*/
void Test_Device(u_char*, const struct pcap_pkthdr*, const u_char*); //Does device work?
void StupidDumpLoopBack(u_char*, const struct pcap_pkthdr*, const u_char*); //Stupid dump
void DecryptLoopBack(u_char*, const struct pcap_pkthdr*, const u_char*); //Decrypt dump
void StupidDumpFileLoopBack(u_char*, const struct pcap_pkthdr*, const u_char*); //Stupid dump a file
void DecryptFileLoopBack(u_char*, const struct pcap_pkthdr*, const u_char*); //Decrypt Dump a File
void StatisticsLoopBack(u_char*, const struct pcap_pkthdr*, const u_char*); //Device Statistics
void SniffUdpPacketsLoopBack(u_char*, const struct pcap_pkthdr*, const u_char*); //UDP Packets sniffer
void IPCaptureLoopBack(u_char*, const struct pcap_pkthdr*, const u_char*); //Host Sniffer
class Sniffer 
{
public:
	Sniffer(); //Constructor which defines all default variable
	~Sniffer(); //Destructor
	void InitDevices(); //Initialize the device list
	void DisplayDevices(pcap_if_t * l_device); //Display the list of device
	char* iptos(u_long in); /*Source code from tcptraceroute (Display an ip addres)*/ 
	std::string ip6tos(struct sockaddr* sockaddr, char* address, int addrlen); //Display an IPV6 IP address (Doesn't work yet isn't implented)
	int GetDeviceNumber(); //Define the number of network devices installed on this computer
	pcap_if_t* GetDevice(); //Return the current device
	pcap_if_t* GetListDevices(); //Return the network device list
	pcap_t* GetCaptureObject(); //Return the capture object
	void OpenDevice(pcap_if_t* l_device, int l_portion,int flag,int Delay); //Open an network device for sniffing packets
    bool IsDeviceWorking(pcap_if_t* l_device); //Test If the device is working
	void StupidDump(pcap_if_t * l_device,std::string l_filename); //Stupid Dump the network
	void DecryptDump(pcap_if_t* l_device,std::string l_filename); //Decrypt Dump the network
	void StupidDumpFile(std::string l_dir); //Stupid dump a file
	void DecryptDumpFile(std::string l_dir); //Decrypt dump a file
	void SniffUdpPackets(pcap_if_t* l_device); //Sniff UDP packets
	void Statistics(pcap_if_t *l_device); //Get Device statistics
	void IpCaptureSniff(pcap_if_t* l_device,std::string l_filename); //Host Capture
	void DisplayHosts(); //Display the Host that we captured before
	void SniffHosts(pcap_if_t* l_device,std::string l_filename); //Sniff some host on the network
	static bool DoesIPAddrExist(ip_address* l_ip_addr); //Is IP ADDRESS EXISTING IN THE HOST CONTAINER
	static void dump(const unsigned char* data_buffer, const unsigned int length); //From the Great Book "Hacking the art of exploitation 2nd Edition by Jon Erickson" (Simply print hexadecimal value of the packets and it's ASCII character)

	static void SigManager(Sniffer* l_sniffer,unsigned int FuncCode); /*This function is used in "loops function" so as to Manage all signals of the sniffer and stop an Capture if CTRL-C is pressed */
	bool DoesFileExist(std::string pszFilename); //Return true if the file exist or false if not
/*Global variables (not the best option ik)*/
	static bool gl_working; //This global variable is used for the function Test_Device()
	static struct SigContainer gl_SigContainer; /*This global variable will be used to know if one of the required signals was pushed*/
	static Sniffer* gl_currentSniffer; //This is a pointer to the last Sniffer Created
	static std::vector<Host> gl_HostContainer; //The network Host Container 
	static ExistingPort* gl_famousPort; //Some famous port defined in Network-Header.h
private:
	pcap_dumper_t* m_SaveFileCapture; //An handle to a save file
	pcap_if_t* m_ListDevices; //List of device installed on the computer
	pcap_if_t* m_Device; //The current device used
	pcap_t* m_CaptureObject; //The capture object
	bool m_flag_IsInitialised; //Is List Devices initialised flag
	bool m_isDeviceWorking; //Is Device Working flag
	char m_errbuf[PCAP_ERRBUF_SIZE]; //Errbuf in case some NpCap function fail
	u_int m_netmask; //The network mask
	struct bpf_program m_fcode; //An bpf program for filter
	struct timeval m_st_ts; //And the current timeval of the capture of an packet
};
namespace SignalSniffer { //All the function that Set to true an Signal flag
	inline void SigIntDecryptDump(int signum) {
		Sniffer::gl_SigContainer.DecryptDumpSig = true;
	}
	inline void SigIntStupidDumpFile(int signum) {
		Sniffer::gl_SigContainer.StupidDumpFileSig = true;
	}
	inline void SigIntDecryptDumpFile(int signum) {
		Sniffer::gl_SigContainer.DecryptFileSig = true;
	}
	inline void SigIntStatistics(int signum) {
		Sniffer::gl_SigContainer.DeviceStatSig = true;
	}
	inline void SigIntSniffUdpPackets(int signum) {
		Sniffer::gl_SigContainer.UDPSnifferSig = true;
	}
	inline void SigIntStupidDump(int signum) {
		Sniffer::gl_SigContainer.StupidDumpSig = true;
	}
	inline void SigIntIpCapture(int signum) {
		Sniffer::gl_SigContainer.IpCaptureSig = true;
	}

}


#endif