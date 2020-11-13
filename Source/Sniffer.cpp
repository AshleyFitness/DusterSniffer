#include "Sniffer.h"
//We must declare statics variable which are mainly used by "extern" function  (extern function are only used when we need to call pcap_loop()
Sniffer* Sniffer::gl_currentSniffer; //Last Sniffer created
bool Sniffer::gl_working; //Is Device working
struct SigContainer  Sniffer::gl_SigContainer; //All signal state
std::vector<Host> Sniffer::gl_HostContainer; //An std::vector of all of the host on which are present on the network
ExistingPort* Sniffer::gl_famousPort; //An structure to all famous protocol name
Sniffer::Sniffer(){ //Simple constructor
	m_CaptureObject = nullptr; 
	m_Device =  new pcap_if_t();
	Sniffer::gl_famousPort= new ExistingPort();
	m_ListDevices = new pcap_if_t();
	m_flag_IsInitialised = false;
	m_netmask = 0;
	m_isDeviceWorking = false;
	Sniffer::gl_working = false;
	Sniffer::gl_currentSniffer = this;
}
Sniffer::~Sniffer(){ //Simple destructor
	delete  m_ListDevices;
	delete m_Device;
	pcap_close(m_CaptureObject);
	delete[] m_errbuf; 
	delete gl_famousPort;
}

/*From tcptraceroute, convert a numeric IP address to a string*/
#define IPTOSBUFFER 12
char* Sniffer::iptos(u_long in) {
	static char output[IPTOSBUFFER][3*4+3+1];
	static short which;
	u_char* p;
	p = (u_char*)&in;
	which = (which + 1 == IPTOSBUFFER ? 0 : which + 1);
	snprintf(output[which],16, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];

}

std::string Sniffer::ip6tos(struct sockaddr* sockaddr, char* address, int addrlen)
{
/*IPV6 Isn't supported yet, If someone find a solution to display IPV6 Console i would be very happy to include it in the program*/
	return "IPV6 Isn't Supported Yet";
}
/*Source code from NPCAP Documentation*/
void Sniffer::DisplayDevices(pcap_if_t * l_device) {
	pcap_addr_t* address;
	char ip6str[128];
	/*Display the name of the device*/
	std::cout << l_device->name << std::endl;

	/*And now the description (if there is one)*/
	if (l_device->description)
		std::cout << "\tDescription: " << l_device->description << std::endl;

	/*Now the loopback address (We must use printf() for this one)*/
	printf("\tLoopback: %s\n", (l_device->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

	/* now we can display those IP addresses*/
	for (address = l_device->addresses; address; address = address->next) {
		std::cout << "\tAddress Family: #" << address->addr->sa_family << std::endl;

		switch (address->addr->sa_family) {
		case AF_INET:
			std::cout << "\tAddress Family Name: AF_INET\n";
			if(address->addr)
				std::cout << "\tAddress: " << iptos(((struct sockaddr_in*)address->addr)->sin_addr.S_un.S_addr) << std::endl;
			if(address->netmask)
				std::cout << "\tNetmask: " << iptos(((struct sockaddr_in*)address->netmask)->sin_addr.S_un.S_addr) << std::endl;
			if (address->broadaddr)
				std::cout << "\tBroadcast Address: " << iptos(((struct sockaddr_in*)address->broadaddr)->sin_addr.S_un.S_addr) << std::endl;
			if (address->dstaddr)
				std::cout << "\tDestination Address: " << iptos(((struct sockaddr_in*)address->dstaddr)->sin_addr.S_un.S_addr) << std::endl;
			break;

		case AF_INET6:
			std::cout << "\tAddress Family Name: AF_INET6\n";
			if(address->addr)
				std::cout << "\tAddress: " << ip6tos(address->addr, ip6str, sizeof(ip6str)) << std::endl;
			break;

		default:
			std::cout << "\tAddress Family Name: Unknown\n";
			break;
		}
	}
	std::cout << std::endl;
}
/*This function is made so as to return the number of device*/
int Sniffer::GetDeviceNumber() {
	int	numOfDevice = 0; 
	for (m_Device = m_ListDevices; m_Device; m_Device = m_Device->next) //Iterating though the list of devices
		numOfDevice++;
	m_Device = nullptr; /*We re-set the value of Device to nullptr so as to avoid error*/
	return numOfDevice; //Returning the number of device
}
void Sniffer::InitDevices() {
/*Initialises the devices list*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &m_ListDevices,m_errbuf) == -1) 
		ErrorHandler::pcap_fatal("pcap_findalldevs_ex()", m_errbuf, false, m_ListDevices); //If it's not working immediatly stop the program

	 m_flag_IsInitialised = true;
}
pcap_if_t* Sniffer::GetDevice() {return m_Device;} //Return an pointer to the device
pcap_if_t* Sniffer::GetListDevices() { return m_ListDevices; } //Return an pointer to the list of device
pcap_t* Sniffer::GetCaptureObject() { return m_CaptureObject; } //Return an pointer to the CaptureObject
/*This functions is basically an wrapper of the pcap_open() function */
void Sniffer::OpenDevice(pcap_if_t* l_device,int l_portion,int flag,int Delay) {
	if ((m_CaptureObject = pcap_open(l_device->name, //name of the device
		l_portion, //Portion of the packet to capture
		flag, //The Correct flag for the option choosed
		Delay, //Read timeout
		NULL, //Authentication on the remote machine
		m_errbuf //Error string
	)) == NULL)
		ErrorHandler::pcap_fatal("pcap_open()", m_errbuf, true, m_ListDevices);

}

/*This function will test if the device manage to get some packet if yes than it mean that devices can sniff!*/
bool Sniffer::IsDeviceWorking(pcap_if_t *l_device) {
	Sniffer::gl_working = false; //Re set the device flag to false 
	m_isDeviceWorking = false; 
	struct timeval st_ts; //Timestamp variable
	if ((m_CaptureObject = pcap_open(l_device->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, m_errbuf)) == NULL) //Trying to open the Device object to sniff packets
		ErrorHandler::pcap_fatal("pcap_open()", m_errbuf, false, l_device);
		
	/*We don't care about the netmask*/
	m_netmask = 0xfffffff;

	//Now we need to compile our filter
	if (pcap_compile(m_CaptureObject, &m_fcode, "tcp", 1, m_netmask) < 0) //ONLY SNIFF TCP traffic
		ErrorHandler::pcap_fatal("pcap_compile()", "Unable to compile the packet filter.", false, l_device);

	//Now set the filter to the Capture Object
	if (pcap_setfilter(m_CaptureObject, &m_fcode) < 0) {
		pcap_close(m_CaptureObject);
		ErrorHandler::pcap_fatal("pcap_compile()", "Error while setting the filter.", false, l_device);
	}
	/*Now we have to put the interface in statics mode */
	if (pcap_setmode(m_CaptureObject, MODE_STAT) < 0) {
		pcap_close(m_CaptureObject);
		ErrorHandler::pcap_fatal("pcap_compile()", "Error while setting the statistics mode.", false, l_device);
	}
	pcap_loop(m_CaptureObject, 10,Test_Device, (PUCHAR)&st_ts); //Loop 10 time the function Test_Device
	//AFTER THE LOOP
	m_isDeviceWorking = Sniffer::gl_working; 
	pcap_close(m_CaptureObject); //We wanna reset the CaptureObject
	return m_isDeviceWorking; //Return if the device can sniff or not
}
/*This function is used in pcap_loop()
 *It's interprating packet with the number of bytes
 * If an Packet have 0 bytes? it mean we didn't manage to sniff a packet
 * IF we managed to sniff one packets at least it mean the device is working and we set the  ISWORKING flag to true
 */
void Test_Device(u_char* state, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	struct timeval* old_ts = (struct timeval*)state; 
	u_int delay; 
	LARGE_INTEGER Bps, Pps; //Bits per second and Packets per second

	/*Calculate the delay in microseconds from the last sample
	 *This value is obtained from the timestamp that is associated with the sample. 
	 */
	delay = (header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;

	/*Get the number of bits per second*/
	Bps.QuadPart = (((*(LONGLONG*)(pkt_data + 8)) * 8 * 1000000) / (delay));
	/*												^		^
													|		|
													|		|
													|		|
							Converts bytes in bits --		|
															|
						delay is expressed in microseconds --
	*/
/*Get the number of packets per second*/
	Pps.QuadPart = (((*(LONGLONG*)(pkt_data)) * 1000000) / (delay));



	if (Bps.QuadPart == 0) //If no bits were found in this packet it mean we didn't managed to sniff a packet
	{
		std::cout << "No packets have been sniffed...\n";
	}
	else { //YAY! We managed to sniff a packet put the flag to true
		std::cout << "Apparently some bits have been found!\n";
		Sniffer::gl_working = true;
	}


	//Store current times
	old_ts->tv_sec = header->ts.tv_sec;
	old_ts->tv_usec = header->ts.tv_usec;
}
/*This mode is the first mode of the Program 
 *It simply sniff packets and display their hex code and ASCII Code
 *In argument we have a pointer to the main device and we have an
 * Filename as well, which is used to save the dump into this file
 * IF no file were defined is defined by default (so l_filename = "")
 * We don't save anything and just print to the screen the capture
 */
void Sniffer::StupidDump(pcap_if_t* l_device,std::string l_filename) {
	Sniffer::gl_SigContainer.StupidDumpSig = false; //We set by default the Signal flag of Stupid dump mode to false (it's used to stop the capture if CTRL-C is pressed)
	//Display title
	system("cls");
	std::cout << "*(((((( [ Stupid Dump ] ))))))*\n";
	std::cout << "--In this Mode you can sniff your network and sniff packets as much as you want--\n";
	std::cout << "--This mode doesn't contain any filter and doesn't decrypt anything,You only get--\n";
	std::cout << "--Some raw byte and we display them...--\n\n";
	std::cout << "How much packet do you want to sniff ? (0 = Infinite) : ";
	bool isAValidNumber = false, isAvalidDelay = false; //Some flag to verify if we entered a valid number and a valid delay (used to leave an loop when we entered the right data)
	std::string strNumOfPacket;  //ALWAYS GET AN STRING WHEN USING STD::CIN
	unsigned int numOfPacket; //Numbers of packet
	while (!isAValidNumber) {//While the data that have been entered is not valid continue to loop
		std::cin >> strNumOfPacket; 
		std::cin.clear();
		if (!strNumOfPacket.empty() && std::all_of(strNumOfPacket.begin(), strNumOfPacket.end(), ::isdigit)) //if it's a number
		{
			numOfPacket = atoi(strNumOfPacket.c_str()); //convert it to an integer
			if (numOfPacket < 0) //And verify if it's a positive number
				std::cout << "[!!] Invalid Choice! Please Make sure your choice is superior to 0\n"; /*This option is not valid*/
			else //IT'S A VALID NUMBER!
				isAValidNumber = true;
		}
		else
			std::cout << "Invalid Number Provided!\n"; /*Wrong Data type*/
	}
	std::cout << "Great! Now that you have selected the numbers of packet! We just need to set-up the delay between each group of packet to display\n";
	std::cout << "You have to express this number in seconds numbers like 2.5 are allowed, so which delay would you like to set : ";

	float DelayBtwPacket; //Basically same than before but this time we are asking for an delay between each time we display an group of packets that we managed to capture
	std::string strDelayBtwPacket; 
	while (!isAvalidDelay) {
		std::cin >> strDelayBtwPacket;
		std::cin.clear();
		try {
			DelayBtwPacket = std::stof(strDelayBtwPacket); //try to convert it to an integer
			if (DelayBtwPacket <= 0)
				std::cout << "[!!] Invalid Choice! Please Make sure your choice is superior to 0\n"; //this option is not valid
			else
				isAvalidDelay = true;
		}
		catch (...) {
			std::cout << "Invalid Number Provided!\n"; //Wrong datatype
			exit(-1);
		}
	}


	//Now that we know the delay seconds number is valid we have to convert it to milliseconds
		DelayBtwPacket *= 1000;
		OpenDevice(l_device, 65536, PCAP_OPENFLAG_PROMISCUOUS, DelayBtwPacket);
		
		if (!l_filename.empty()) { //If an savefile has been defined
		
			m_SaveFileCapture = pcap_dump_open(m_CaptureObject, (const char*)l_filename.c_str()); //Open the file and start writing all the capture in 
			if (m_SaveFileCapture == NULL)  //If something failed
				ErrorHandler::pcap_fatal("pcap_dump_open()", "Error while opening the dump file...", true, l_device); //Shutdown the program immediatly
			else
				std::cout << "Saving Dump on " << l_filename << std::endl;
		}

		std::cout << "\nSniffing on " << l_device->description << "...\n";
		std::cout << "Press CTRL+C to stop the sniffing\n";
		system("pause");
		pcap_loop(m_CaptureObject, numOfPacket, StupidDumpLoopBack , (u_char*)m_SaveFileCapture); //WE ARE CAPTURING <NUMBERSOFPACKETTHATTHEUSERENTERED> packets
		//After the loop
		system("pause");
		if(m_SaveFileCapture!=nullptr) //If an save file has been defined close the file
		pcap_dump_close(m_SaveFileCapture);
		pcap_close(m_CaptureObject); //close the capture object
}
//From the Great Book "Hacking the art of exploitation 2nd Edition by Jon Erickson"
//Just display hex code and ascii code
void Sniffer::dump(const unsigned char* data_buffer, const unsigned int length) {
	unsigned char byte;
	unsigned int i, j;

	for (i = 0; i < length; i++) {
		byte = data_buffer[i];
		printf("%02x ", data_buffer[i]); //Display one byte in hexadecimal
		if (((i % 16) == 15) || (i == length - 1)) {
			for (j = 0; j < 15 - (i % 16); j++)
				printf("  ");
			printf("| ");
			for (j = (i - (i % 16)); j <= i; j++) { //Only display the bytes that are displayable (check http://www.asciitable.com/ for more detail)
				byte = data_buffer[j];
				if ((byte > 31) && (byte < 127)) //Bytes between 31 and 127 can be displayed
					printf("%c", byte);
				else
					printf(".");
			}
			printf("\n"); //End of a line (16 bytes reached)
		}  //End of the if statement
	} //End of the for statement
}
/*This is the function used in pcap_loop()*/
void StupidDumpLoopBack(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	std::cout << "Found " << header->len << " bytes, at : "; //display how much bytes we found
	time_t now = header->ts.tv_sec; //Create an timestamp of the moment of the capture
	std::tm gmt_time{}; 
	localtime_s(&gmt_time, &now);//convert it to an tm structure
	std::cout << gmt_time.tm_hour << ":" << gmt_time.tm_min << ":" << gmt_time.tm_sec << std::endl; //And display the capture time
	Sniffer::dump(pkt_data, header->len); //Display the packet
	if(param != nullptr) //If an save file has been defined
	pcap_dump(param, header, pkt_data); //Save data in this file 

	Sniffer::SigManager(Sniffer::gl_currentSniffer, STUPID_DUMP); //Verify if we pressed CTRL-C
}
/*The signal manager is often used when pressing CTRL-C In some Function so as to stop pcap_loop()*/
void Sniffer::SigManager(Sniffer *l_sniffer,unsigned int FuncCode) {

	switch (FuncCode) {
	case STUPID_DUMP_FILE:
		signal(SIGINT,SignalSniffer::SigIntStupidDumpFile);
		if (Sniffer::gl_SigContainer.StupidDumpFileSig) { //If the flag is true
			std::cout << "Stopping the file sniffing...\n"; //stop the execution of the loop
			pcap_breakloop(l_sniffer->GetCaptureObject());
		}
		break;
	case DECRYPT_DUMP:
		signal(SIGINT, SignalSniffer::SigIntDecryptDump);
		if (Sniffer::gl_SigContainer.DecryptDumpSig) {
			std::cout << "Stopping the sniffing...\n";
			pcap_breakloop(l_sniffer->GetCaptureObject());
		}
		break;
	case STUPID_DUMP:
		signal(SIGINT, SignalSniffer::SigIntStupidDump);
		if (Sniffer::gl_SigContainer.StupidDumpSig) {
			std::cout << "Stopping the sniffing...\n";
			pcap_breakloop(l_sniffer->GetCaptureObject());
		}
		break;
	case DECRYPT_DUMP_FILE:
		signal(SIGINT, SignalSniffer::SigIntDecryptDumpFile);
		if (Sniffer::gl_SigContainer.DecryptFileSig)
		{
			std::cout << "Stopping the file sniffing...\n";
			pcap_breakloop(l_sniffer->GetCaptureObject());
		}
		break;
	case DEVICE_STAT:
		signal(SIGINT, SignalSniffer::SigIntStatistics);
		if (Sniffer::gl_SigContainer.DeviceStatSig) {
			std::cout << "Stopping the Statistics gathering...\n";
			pcap_breakloop(l_sniffer->GetCaptureObject());
		}
		break;
	case UDP_SNIFFER:
		signal(SIGINT, SignalSniffer::SigIntSniffUdpPackets);
		if (Sniffer::gl_SigContainer.UDPSnifferSig) {
			std::cout << "Stopping the UDP network sniffer...\n";
			pcap_breakloop(l_sniffer->GetCaptureObject());
		}
		break;
	case IpCapture:
		signal(SIGINT, SignalSniffer::SigIntIpCapture);
		if (Sniffer::gl_SigContainer.IpCaptureSig) {
			std::cout << "Stopping the Host Scanning...\n";
			pcap_breakloop(l_sniffer->GetCaptureObject());
		}
		break;
	}

}
/*Decrypt dump mode
 * the second mode of the program
 * In contrary of the first mode this time
 * We display a lot of data like 
 * the destination the source, the type the flags in this packets and much more
 * IT'S WAY MORE READABLE THEN THE FIRST MODE
 */
void Sniffer::DecryptDump(pcap_if_t* l_device,std::string l_filename) {
	Sniffer::gl_SigContainer.DecryptDumpSig = false; //Always set the signal flag to false by default
	//Display the title
	system("cls");
	std::cout << "__|___|___|__| [ Decrypt Dump ] |__|___|___|__\n";
	std::cout << "--In this mode you can sniff your network and sniff packets as much as you want\n";
	std::cout << "--This mode allows you to decrypt those packets there is only one filter that--\n";
	std::cout << "--Only allow to sniff ETHERNET,IP AND TCP packets but at least it's easier to see what's happening...--\n";
	std::cout << "[!!] WARNING IPV6 ISN'T SUPPROTED YET! (so it can lead to some junk data).\n";
	std::cout << "How much packet do you want to sniff (0 = Infinite) : ";
	bool isAValidNumber = false,isAvalidDelay=false; //Flag to verify if we entered the right data and not JUNK data
	std::string strNumOfPacket;
	unsigned int numOfPacket;
	while (!isAValidNumber) { //While it's not an valid data
		std::cin >> strNumOfPacket;
		std::cin.clear();
		if (!strNumOfPacket.empty() && std::all_of(strNumOfPacket.begin(), strNumOfPacket.end(), ::isdigit)) //if it's an number
		{
			numOfPacket = atoi(strNumOfPacket.c_str()); //Convert to an integer
			if (numOfPacket < 0) //If it's not an positive number
				std::cout << "[!!] Invalid Choice! Please Make sure your choice is superior to 0\n"; /*This option is not valid*/
			else
				isAValidNumber = true; //A good number
		}
		else
			std::cout << "Invalid Number Provided!\n"; /*Wrong Data type*/
	}

	std::cout << "Great! Now that you have selected the numbers of packet! We just need to set-up the delay between each group of packet to display\n";
	std::cout << "You have to express this number in seconds numbers like 2.5 are allowed, so which delay would you like to set : ";
	//Get the delay same as before
	float DelayBtwPacket;
	std::string strDelayBtwPacket;
	while (!isAvalidDelay) {
		std::cin >> strDelayBtwPacket;
		std::cin.clear();
		try {
			DelayBtwPacket = std::stof(strDelayBtwPacket);
			if (DelayBtwPacket <= 0)
				std::cout << "[!!] Invalid Choice! Please Make sure your choice is superior to 0\n"; //this option is not valid
			else
				isAvalidDelay = true;
		}
		catch (...) {
			std::cout << "Invalid Number Provided!\n"; //Wrong datatype
		}
	}
	DelayBtwPacket *= 1000; //convert to miliseconds
	OpenDevice(l_device, 65536, PCAP_OPENFLAG_PROMISCUOUS, DelayBtwPacket); //Open the device

	std::string packet_filter = "ip and tcp"; //ONLY CAPTURE ETHERNET,IP AND TCP

	/*Check the link layer. We support only Ethernet for simplicity*/
	if (pcap_datalink(m_CaptureObject) != DLT_EN10MB)
		ErrorHandler::pcap_fatal("pcap_datalink()", "Sorry this program only works on Ethernet networks.", true, l_device);
	if (l_device->addresses != NULL)
		m_netmask = ((struct sockaddr_in*)(l_device->addresses->netmask))->sin_addr.S_un.S_addr; //Set the netmask to the device netmask
	else {
		/*If the interface is without addresses we suppose to be in a C class network */
		m_netmask = 0xffffff;
	}
	//Compile the filter
	if (pcap_compile(m_CaptureObject, &m_fcode, packet_filter.c_str(), 1, m_netmask) < 0)
		ErrorHandler::pcap_fatal("pcap_compile()", "Unable to compile the packet filter. Something is wrong with the syntax.\n",true,l_device);
	//Set the filter
	if (pcap_setfilter(m_CaptureObject, &m_fcode) < 0)
		ErrorHandler::pcap_fatal("pcap_setfilter()", "Error Setting the filter.", true, l_device);
	if (!l_filename.empty()) { //If an save file has been defined open the file and save capture into the file

		m_SaveFileCapture = pcap_dump_open(m_CaptureObject, (const char*)l_filename.c_str());
		if (m_SaveFileCapture == NULL)
			ErrorHandler::pcap_fatal("pcap_dump_open()", "Error while opening the dump file...", true, l_device);
		else
			std::cout << "Saving Dump on " << l_filename << std::endl;
	}
		std::cout << "\nSniffing on " << l_device->description << "...\n";
		std::cout << "Press CTRL+C to stop the sniffing\n";
		system("pause");
		pcap_loop(m_CaptureObject, numOfPacket, DecryptLoopBack, (u_char *)m_SaveFileCapture);
		//After the loop
		system("pause");
		if(m_SaveFileCapture!=nullptr) //If a save file is defined close it
		pcap_dump_close(m_SaveFileCapture);
		pcap_close(m_CaptureObject);
}
void DecryptLoopBack(u_char*param, const struct pcap_pkthdr*header, const u_char*packet) {

	int tcp_header_length, total_header_size, pkt_data_len; //some integers to get length of the packet,the tcp header length,the total header size
	u_char* pkt_data; //The data of an packet
	std::cout << "====Received a packet of " << header->len << " bytes====\n"; //Display the length of the packet
	decode_ethernet(packet); //Display ethernet data (at the beginning of the packet)
	decode_ip(packet + ETHER_HDR_LEN); //Display IP data (position = beginning of the packet + 14 BYTES (14 BYTES IS AN ETHERNET HEADER))
	tcp_header_length = decode_tcp(packet + ETHER_HDR_LEN + IP_HDR_LEN);//Display TCP data (position = beginning of the packet + 14 bytes + 20 bytes (which corresponds to an IP header))
	total_header_size = ETHER_HDR_LEN + IP_HDR_LEN + tcp_header_length; //16+20+TCP HEADER LENGTH
	pkt_data = (u_char*)packet + total_header_size; //Packet data is set located after all header

	pkt_data_len = header->len - total_header_size; 
	if (pkt_data_len > 0) { //if there is data
		std::cout << "\t\t\t" << pkt_data_len << " bytes of packet data.\n";
		Sniffer::dump(pkt_data, pkt_data_len); //Display the data
	}
	else //No data
		std::cout << "\t\t\tNo data found in this packet.\n";
	if (param != nullptr) //if a file has been defined save data in
		pcap_dump(param, header, packet);
	Sniffer::SigManager(Sniffer::gl_currentSniffer, DECRYPT_DUMP); //Verify if CTRL-C is pressed
}

//Return true if the file exist and false if not
bool Sniffer::DoesFileExist(std::string FileName)
{
	LPCSTR pszFileName;
	pszFileName = FileName.c_str();
	DWORD dwAttrib = GetFileAttributes(pszFileName);
	if (!(dwAttrib & FILE_ATTRIBUTE_DEVICE) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) { //if it's not an directory abd it exist
		return true;
	}
	return false;

}
/*This function is very similar to the first one
 *But this time we aren't sniffing the network but an capture file
 */
void Sniffer::StupidDumpFile(std::string l_dir) {
	Sniffer::gl_SigContainer.StupidDumpFileSig = false; //Always set by default the Signal flag to false
	//Display title
	system("cls");
	std::cout << "@@@=---=@@@ { Stupid Dump File } @@@=---=@@@\n";
	std::cout << "--This mode is pretty similar to the Stupid Dump Mode--\n";
	std::cout << "--Basically it's does the same thing except that this--\n";
	std::cout << "--time we are sniffing a file and not a network.\n";
	std::cout << "Please Choose a file (that is in the same directory than this program or with a correct path) : ";
	char source[PCAP_BUF_SIZE]; 
	std::string filename; //The first variable store the content and the second is the filename 
	bool FileExist = false,isAvalidDelay=false; //Boolean that keep track if we entered an valid input
	if (l_dir == "./") //If the default directory is set by default "./"  which mean default directory set the directory to NULL
		l_dir = "";
	while (!FileExist) { //While we didn't found the file loop
		std::ostringstream osFilename; //An string stream used for Putting the DIRECTORY (if defined) + the filename
		osFilename << l_dir; //Put the directory first so the string look like this "DIRECTORY/"
		std::cin >> filename;  //ask for input
		std::cin.clear();
		osFilename << filename; //Add the filename and now the string look like this "DIRECTORY/FILE.pcap"
		filename = osFilename.str(); //and set the filename to the stream
		osFilename.str(""); //put the stream to NULL
		if (DoesFileExist(filename) == true) //If the filename exist verify it's an pcap file
		{
			if (filename.substr(filename.find_last_of(".") + 1) == "pcap") 
				FileExist = true;
			else
				std::cout << "This is not an pcap file!\n"; //It's not an pcap file
		}
		else  //the file doesn't exist
			std::cout << "Sorry your file doesn't exist!\n";
	}
/* Create the source string */
	if (pcap_createsrcstr(source,
		PCAP_SRC_FILE, //We want to open a file
		NULL, //Remote Host
		NULL,//port on the remote host
		filename.c_str(), //Name of the file that we want to open
		m_errbuf//error buffer
	) != 0)
		ErrorHandler::pcap_fatal("pcap_createsrcstr()", m_errbuf, false, nullptr);


	std::cout << "Great! Now that you have selected the file! We just need to set-up the delay between each group of packet to display\n";
	std::cout << "You have to express this number in seconds numbers like 2.5 are allowed, so which delay would you like to set : ";
	//Same than before ask for delay,check if it's a number and superior to 0
	float DelayBtwPacket;
	std::string strDelayBtwPacket;
	while (!isAvalidDelay) {
		std::cin >> strDelayBtwPacket;
		std::cin.clear();


		try {
			DelayBtwPacket = std::stof(strDelayBtwPacket);
			if (DelayBtwPacket <= 0)
				std::cout << "[!!] Invalid Choice! Please Make sure your choice is superior to 0\n"; //this option is not valid
			else
				isAvalidDelay = true;
		}
		catch (...) {
			std::cout << "Invalid Number Provided!\n"; //Wrong datatype
		}
	}
	DelayBtwPacket *= 1000;
	/*Open the capture file*/
	if ((m_CaptureObject = pcap_open(source, //Name of the device
		65536, //portion of the packet to capture
		PCAP_OPENFLAG_PROMISCUOUS, //Promiscuous mode
		DelayBtwPacket, //Read timeout
		NULL, //Authentication on the remote machine
		m_errbuf //error buffer
	)) == NULL)
		ErrorHandler::pcap_fatal("pcap_open()", m_errbuf, false, nullptr);
	std::cout << "Get Ready to sniff " << filename << " !\n";
	system("pause");
	//Read and dispatch packets until EOF is reached
	pcap_loop(m_CaptureObject,0, StupidDumpFileLoopBack, NULL);
	//After the loop
	system("pause");
	pcap_close(m_CaptureObject);
}
void StupidDumpFileLoopBack(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {

	/*UNUSED VARIABLE*/
	(VOID)param;
	Sniffer::dump(pkt_data, header->len); //Display HEX and ASCII code
	std::cout << "\n\n"; //and two end line
	Sniffer::SigManager(Sniffer::gl_currentSniffer, STUPID_DUMP_FILE); //verify if we pressed CTRL-C
}
/*Very similar to stupid dump a file but this time instead of basing ourself on the stupid mode to open a file
 *We use instead the decrypt mode
 */
void Sniffer::DecryptDumpFile(std::string l_dir)
{
	Sniffer::gl_SigContainer.DecryptFileSig = false; //Always set the signal flag to false by default
	//Display title
	system("cls");
	std::cout << "::'';; = = = { Decrypt Dump File } = = = ;;''::\n";
	std::cout << "--This mode is pretty similar to the Decrypt Dump Mode--\n";
	std::cout << "--Basically it's does the same thing except that this--\n";
	std::cout << "--time we are sniffing a file and not a network.\n";
	std::cout << "[!!] Warning! This can lead to junk data since we can't really verify if there is only TCP,IP and ETHERNET\n";
	std::cout << "Please Choose a file (that is in the same directory than this program or with a correct path) : ";
	char source[PCAP_BUF_SIZE];
	std::string filename; //The first variable store the content and the second is the filename 
	bool FileExist = false, isAvalidDelay = false;
	if (l_dir == "./") //If the directory is DEFAULT set it to NULL
		l_dir = "";
	while (!FileExist) {
		std::ostringstream osFilename; //Used to insert the directory and the filename
		osFilename << l_dir; //insert the directory first
		std::cin >> filename;
		std::cin.clear();  //Ask for input
		osFilename << filename; //insert the filename
		filename = osFilename.str(); //convert the file stream to an std::string
		osFilename.str(""); //Clear the file stream
		if (DoesFileExist(filename) == true) { //if it exist
			if (filename.substr(filename.find_last_of(".") + 1) == "pcap") //verify that it's an .pcap file
				FileExist = true;
			else //not an pcap file
				std::cout << "This is not an pcap file!\n";
		}
		else //File doesn't exist
			std::cout << "Sorry your file doesn't exist!\n";
	}
	if (pcap_createsrcstr(source,
		PCAP_SRC_FILE, //We want to open a file
		NULL, //Remote Host
		NULL,//port on the remote host
		filename.c_str(), //Name of the file that we want to open
		m_errbuf//error buffer
	) != 0)
		ErrorHandler::pcap_fatal("pcap_createsrcstr()", m_errbuf, false, nullptr);

	std::cout << "Great! Now that you have selected the file! We just need to set-up the delay between each group of packet to display\n";
	std::cout << "You have to express this number in seconds numbers like 2.5 are allowed, so which delay would you like to set : ";
	 //Ask for delay very similar to before
	float DelayBtwPacket;
	std::string strDelayBtwPacket;
	while (!isAvalidDelay) {
		std::cin >> strDelayBtwPacket;
		std::cin.clear();
		try {
			DelayBtwPacket = std::stof(strDelayBtwPacket);
			if (DelayBtwPacket <= 0)
				std::cout << "[!!] Invalid Choice! Please Make sure your choice is superior to 0\n"; //this option is not valid
			else
				isAvalidDelay = true;
		}
		catch (...) {
			std::cout << "Invalid Number Provided!\n"; //Wrong datatype
		}
	}
	DelayBtwPacket *= 1000; //convert seconds to milliseconds
	if ((m_CaptureObject = pcap_open(source, //Name of the device
		65536, //portion of the packet to capture
		PCAP_OPENFLAG_PROMISCUOUS, //Promiscuous mode
		DelayBtwPacket, //Read timeout
		NULL, //Authentication on the remote machine
		m_errbuf //error buffer
	)) == NULL)
		ErrorHandler::pcap_fatal("pcap_open()", m_errbuf, false, nullptr);

	std::cout << "Get Ready to sniff " << filename << " !\n";
	system("pause");
	pcap_loop(m_CaptureObject, 0, DecryptFileLoopBack, NULL); //Display the whole file
	//After the loop
		pcap_close(m_CaptureObject); 
		system("pause");

}
void DecryptFileLoopBack( u_char* param,const  struct pcap_pkthdr* header, const u_char* packet) {
	int tcp_header_length, total_header_size, pkt_data_len; //All the header size,pkt data length and tcp header size
	u_char* pkt_data;
	std::cout << "====Received a packet of " << header->len << " bytes ====\n"; //Display how much bytes we received
	decode_ethernet(packet); //Decode ethernet part of the packet
	decode_ip(packet + ETHER_HDR_LEN); //Decode IP part of the packet
	tcp_header_length = decode_tcp(packet + ETHER_HDR_LEN + IP_HDR_LEN); //Decode TCP part of the packet
	total_header_size = ETHER_HDR_LEN + IP_HDR_LEN + tcp_header_length; //16+20+TCP HEADER SIZE
	pkt_data = (u_char*)packet + total_header_size; //Set the pkt data after all headers

	pkt_data_len = header->len - total_header_size; //Length of the pkt data
	if (pkt_data_len > 0) { //if there is data
		std::cout << "\t\t\t" << pkt_data_len << " bytes of packet data.\n";
		Sniffer::dump(pkt_data, pkt_data_len); //Display the packet data
	}
	else //No data in this packet
		std::cout << "\t\t\tNo data found in this packet.\n";
	Sniffer::SigManager(Sniffer::gl_currentSniffer, DECRYPT_DUMP_FILE); //Verify if CTRL-C is pressed
}
/*This Mode is very simple
 *To be honest it's very similar to the "TEST DEVICE mode"
 * But this time we don't really want to test anything
 * Just to display how much packets per second and bits per second we can sniff
 */
void Sniffer::Statistics(pcap_if_t* l_device) {
	Sniffer::gl_SigContainer.DeviceStatSig = false; //Always set the Signal flag to false by default
	//Display title
	std::cout << "[]{}();;;{{{ DEVICE STATISTICS ! }}};;;\n";
	std::cout << "--Welcome in this mode! In this mode you can get some pretty intersting--\n";
	std::cout << "--statistics about your device that you are using for sniffing packets--\n";
	std::cout << "--Firstly we display all information about your device and secondly we display--\n";
	std::cout << "--we display how much packets/bits your device can sniff in one second--\n";
	std::cout << "--How much time do you want to sniff a packet ? (0 = Infinite) : ";
	bool isAValidNumber = false,isAvalidDelay=false; //Two flag to verify if the input is valid
	std::string strNumOfPacket; 
	unsigned int numOfPacket;
	while (!isAValidNumber) { //While the input isn't valid
		std::cin >> strNumOfPacket;
		std::cin.clear(); //Ask for input
		if (!strNumOfPacket.empty() && std::all_of(strNumOfPacket.begin(), strNumOfPacket.end(), ::isdigit)) //if the input is a humber
		{
			numOfPacket = atoi(strNumOfPacket.c_str()); //convert the string to an integer
			if (numOfPacket < 0) //If it's not an positive number
				std::cout << "[!!] Invalid Choice! Please Make sure your choice is superior to 0\n"; /*This option is not valid*/
			else //VALID NUMBER
				isAValidNumber = true;
		}
		else
			std::cout << "Invalid Number Provided!\n"; /*Wrong Data type*/
	}
	/*ASK WHICH TYPE OF TRAFFIC WE WANNA SNIFF*/
	std::cout << "Well,well We are almost done for gathering statistics! We just need one more piece to the cake.\n";
	std::cout << "We will need to know which type of traffic you would like to gather statistics!\n";
	std::cout << "1) No filter, All the traffic.\n";
	std::cout << "2) Only UDP traffic.\n";
	std::cout << "3) Only TCP traffic.\n";
		int numTrafficChoice;
		std::string strNumTrafficChoice;
		bool isAValidTraffic = false;
		while (!isAValidTraffic) { //While it's not a valid traffic number
			std::cin >> strNumTrafficChoice;
			std::cin.clear(); //Ask for input
			try {
				numTrafficChoice = std::stof(strNumTrafficChoice); //try to convert it to an integer 
				if (numTrafficChoice <= 0 && numTrafficChoice > 3) //If it's btw 1 and 3
					std::cout << "[!!] Invalid Choice! Please Make sure your choice is between 1 and 3\n"; //this option is not valid
				else //IT'S A VALID NUMBER!
					isAValidTraffic = true;
			}
			catch (...) {
				std::cout << "Invalid Number Provided!\n"; //Wrong datatype
			}
		}
		DisplayDevices(l_device); //Display some stat about the device we are using
	std::string mode;  
	switch (numTrafficChoice) { //Set the mode string to the number we choosed
	case 1:
		mode = "";
		break;
	case 2:
		mode = "udp";
		break;
	case 3:
		mode = "tcp";
		break;
	}
	//We open the Sniffing device
	OpenDevice(l_device, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000);
	//We don't care about the netmask just leave it like that
	m_netmask = 0xffffff;
	//Compile the filter
	if (pcap_compile(m_CaptureObject, &m_fcode, mode.c_str(), 1, m_netmask) < 0)
		ErrorHandler::pcap_fatal("pcap_compile()", "Unable to compile the packet filter. Something is wrong...", true, l_device);
	//Now we can set the filter
	if (pcap_setfilter(m_CaptureObject, &m_fcode) < 0)
	{
		pcap_close(m_CaptureObject);
		ErrorHandler::pcap_fatal("pcap_setfilter()", "Error while setting the filter.\n", true, l_device);
	}
	/*We need to put the interface in statstics mode*/
	if (pcap_setmode(m_CaptureObject, MODE_STAT) < 0)
	{
		pcap_close(m_CaptureObject);
		ErrorHandler::pcap_fatal("pcap_setmode()", "Error while setting the mode.\n",true,l_device);
	}
	if (mode == "") { //If there is no filter print that we choosed NO FILTER
		mode = "(NO FILTER)";
		std::cout << mode;
	}
	else 
		for (int i = 0; i < mode.length(); i++) //Loop through the string
			putchar(toupper(mode.c_str()[i])); //It's my little personal touch i find it better to display the protocol name in capital letter
	std::cout << " Trafic Summary: (Press CTRL+C to stop)\n";
	system("pause");
	pcap_loop(m_CaptureObject, numOfPacket, StatisticsLoopBack, (PUCHAR)&m_st_ts);
	//After loop
	pcap_close(m_CaptureObject);
	system("pause");
}
//This function is used in pcap_loop()
//It's display how much bits and packets per seconds we managed to sniff
void StatisticsLoopBack(u_char* state, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	struct timeval* old_ts = (struct timeval*)state; //Timestamp
	u_int delay; //Delay
	LARGE_INTEGER Bps, Pps; //Those variables describes the number of bytes,packets per seconds that we can sniff
	struct tm ltime; //Used for displaying the time capture
	char timestr[16]; //String for the time
	time_t local_tv_sec; //Timestamp
	/*Calculate the delay in microseconds from the last sample
	 *This value is obtained from the timestamp that is associated with the sample.
	 */
	delay = (header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
	/*Get the number of bits per second*/
	Bps.QuadPart = (((*(LONGLONG*)(pkt_data + 8)) * 8 * 1000000) / (delay));
	/*												^		^
													|		|
													|		|
													|		|
							Converts bytes in bits --		|
															|
						delay is expressed in microseconds --
	*/
	/*Get the number of packets per second*/
	Pps.QuadPart = (((*(LONGLONG*)(pkt_data)) * 1000000) / (delay));
	//convert the timestamp to an readable format
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);

	/*Print the timestamp*/
	printf("%s ", timestr);
	/*Print the samples*/
	printf("BPS=%I64u", Bps.QuadPart);
	printf("PPS=%I64u\n", Pps.QuadPart);
	//Store current times
	old_ts->tv_sec = header->ts.tv_sec;
	old_ts->tv_usec = header->ts.tv_usec;
	Sniffer::SigManager(Sniffer::gl_currentSniffer, DEVICE_STAT); //Verify if CTRL-C is pressed
}
/*This is not an very important mode tbh
 *This mode allows you to display every UDP connection that happened
 * in the network
 * If  you are pretty good at networking you must know that
 * UDP packets doesn't really contain important data (i mean it's possible but like you must be crazy to transfer important data using UDP protcol)
 */
void Sniffer::SniffUdpPackets(pcap_if_t *l_device) {
	Sniffer::gl_SigContainer.UDPSnifferSig = false; //Always set the Signal Flag to false by default
	//Display the title
	system("cls");
	std::cout << "____---___|||| Snif UDP PACKETS ||||___---____\n";
	std::cout << "--If you are pretty good at networking, you must know that UDP packets are very different from TCP packets--\n";
	std::cout << "--While TCP packets contain a lot of data like TLS,Flags,Seq,Ack and much more--\n";
	std::cout << "--So trying to sniff and decrypt UDP packets is quite useless--\n";
	std::cout << "--Instead, we can just try to see which computer is trying to communicate on the network--\n";
	std::cout << "How much packets do you want to sniff ? (0 = Infinite) : ";
	bool isAValidPacket = false; //Flag Is A valid Number that the  user entered
	std::string strNumPacket;
	int numPacket;
	while (!isAValidPacket) { //While it's not a valid data continue to loop
		std::cin >> strNumPacket;
		std::cin.clear(); //Ask for input
		try {
			numPacket = std::stof(strNumPacket); //try to convert an string to an integer
			if (numPacket < 0) //if it's not a positive number
				std::cout << "[!!] Invalid Choice! Please Make sure your choice is a positive number\n"; //this option is not valid
			else
				isAValidPacket = true;
		}
		catch (...) {
			std::cout << "Invalid Number Provided!\n"; //Wrong datatype
		}
	}
	OpenDevice(l_device, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000);
	/*We only accept Ethernet*/
	if (pcap_datalink(m_CaptureObject) != DLT_EN10MB)
		ErrorHandler::pcap_fatal("pcap_datalink()", "This program only work with Ethernet", true, l_device);
	
	/*Now we check the netmask*/
	if (l_device->addresses != NULL)
		/*Retrieve the mask of the first address of the interface*/
		m_netmask = ((struct sockaddr_in*)(l_device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/*If there is no addresses we suppose to be in a C class network*/
		m_netmask = 0xffffff;

	//Now we need to compile our filter
	if (pcap_compile(m_CaptureObject, &m_fcode, "ip and udp", 1, m_netmask) < 0) //ONLY SNIFF IP AND UDP
		ErrorHandler::pcap_fatal("pcap_compile()", "Unable to compile the packet filter. Something is wrong in the syntax...\n",true,l_device);
	if (pcap_setfilter(m_CaptureObject, &m_fcode) < 0)
		ErrorHandler::pcap_fatal("pcap_setfilter()", "Error while setting the filter.", true, l_device);
	
	std::cout << "\nSniffing on " << l_device->description << "... (PRESS CTRL+C to stop)\n";
	system("pause");
	pcap_loop(m_CaptureObject, numPacket, SniffUdpPacketsLoopBack, NULL);
	//After loop
	pcap_close(m_CaptureObject);
	system("pause");
}
/*This function is used in pcap_loop()
 *It's allowing us to sniff and display all the UDP traffics
 */
void SniffUdpPacketsLoopBack(u_char *param,const struct pcap_pkthdr *header,const u_char *pkt_data) {
	struct tm ltime; //Time structure used to display time
	char timestr[16]; //time string
	time_t local_tv_sec; //Timestamp
	u_short sport, dport; //Source and destination UDP port 
	ip_hdr* ih; //Ip header used to display IP protocol information
	udp_hdr* uh; //UDP header used to display UDP protocol information
	/*Useless
	Variable
	*/
	(VOID)(param);

	//convert the timestamp to an readable format
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);

	/*Print the timestamp*/
	printf("%s len:%d ", timestr,header->len);
	decode_udp(pkt_data + ETHER_HDR_LEN,pkt_data + ETHER_HDR_LEN + IP_HDR_LEN); //Display each UDP connection
	Sniffer::SigManager(Sniffer::gl_currentSniffer, UDP_SNIFFER); //Verify if CTRL-C is pressed
}
/*This mode is kinda the "BEST SELLER" of this program
 *This mode is one of the most complex of the program
 *It's allowing you to sniff the network
 *And display ALL Opened port we found and all the IP address on the network
 * [!!] IT'S NOT AN PORT SCANNER We just interprate each packets
 *And when an new port is detected on the host we add it to the host port list
 * IT MEAN, IF AN HOST HAS FOR EXAMPLE AN FTP server
 *But when you sniff the network and no one try to connect to the FTP server of the host
 *You will never be able to find that this host has actually an FTP server
*/
void Sniffer::IpCaptureSniff(pcap_if_t *l_device,std::string l_filename){
	Sniffer::gl_SigContainer.IpCaptureSig = false; //Set the Signal flag by default to false
	//Display the title
	system("cls");
	std::cout << ":):):):) Ip Capture Sniff :(:(:(:(\n";
	std::cout << "--In this mode you can try to get all the connected IP addressed--\n";
	std::cout << "--That are connected on the network that you are trying to sniff--\n";
	std::cout << "--Your device will try to get all the ip addresses that he can get--\n";
	std::cout << "--And he will try to display their port.--\n";
	std::cout << "--[!!] THIS PROGRAM IS NOT AN PORT SCANNER YET WE ARE JUST SNIFFING THE PACKETS AND TRYING TO GET INFORMATION WITH WHAT WE FIND!\n";
	std::cout << "--In this mode you have two option you mush choose between those 2 options--\n";
	std::cout << "1) Sniff IP Addresses and Opened Port\n";
	std::cout << "2) Display Information(You must sniff information first)\n";
	std::cout << "Select your choice : ";
	std::string strChoice; 
	int Choice;
	bool isAValidChoice=false; //Flag to verify it's an valid input
	while (!isAValidChoice) { //While it's not an valid input continue to loop
		std::cin >> strChoice;
		std::cin.clear(); //Get the input
		try {
			Choice = std::stof(strChoice); //Convert the string to an integer
			if (Choice < 1 && Choice > 2)//If Choice is not equal to one or two
				std::cout << "[!!] Invalid Choice! Please Make sure your choice is equal to one or two\n"; //this option is not valid
			else //VALID NUMBER!
				isAValidChoice = true;
		}
		catch (...) {
			std::cout << "Invalid Number Provided!\n"; //Wrong datatype
		}
	}
	if (Choice == 1) 
		SniffHosts(l_device,l_filename);
	else
		DisplayHosts();
}
/*This function is the first option of the Host Capture
 *Here is what it is doing, Setting up the capture device option,
 *call pcap_loop() and saving the data we captured into a log file if defined
 */
void Sniffer::SniffHosts(pcap_if_t* l_device,std::string l_filename) {
	
	OpenDevice(l_device, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000); //Open the capture device
	std::string packet_filter = "ip and tcp"; //defined a packet filter (only capture ETHERNET,IP and TCP traffic)

	/*Check the link layer. We support only Ethernet for simplicity*/
	if (pcap_datalink(m_CaptureObject) != DLT_EN10MB)
		ErrorHandler::pcap_fatal("pcap_datalink()", "Sorry this program only works on Ethernet networks.", true, l_device);
	if (l_device->addresses != NULL)
		m_netmask = ((struct sockaddr_in*)(l_device->addresses->netmask))->sin_addr.S_un.S_addr;
	else {
		/*If the interface is without addresses we suppose to be in a C class network */
		m_netmask = 0xffffff;
	}
	//Compile the filter
	if (pcap_compile(m_CaptureObject, &m_fcode, packet_filter.c_str(), 1, m_netmask) < 0)
		ErrorHandler::pcap_fatal("pcap_compile()", "Unable to compile the packet filter. Something is wrong with the syntax.\n", true, l_device);
	//Set the filter
	if (pcap_setfilter(m_CaptureObject, &m_fcode) < 0)
		ErrorHandler::pcap_fatal("pcap_setfilter()", "Error Setting the filter.", true, l_device);
		

	std::cout << "\nSniffing on " << l_device->description << "...\n";
	std::cout << "Press CTRL+C to stop the sniffing\n";
	system("pause");
	auto start = std::chrono::system_clock::now(); //Get the value of when the capture started
	pcap_loop(m_CaptureObject, 0, IPCaptureLoopBack, NULL);
	//After the loop
	pcap_close(m_CaptureObject); //Close the capture object like always
	if (l_filename.empty()) //If the file is empty we don't need to continue
	{
		system("pause");
		return (void)-1; //stop the execution
	}
	auto end = std::chrono::system_clock::now(); //Get the value when did the host capture ended
	std::chrono::duration<double> elapsed_time = end - start; //Elapsed time how much the capture took end - start
	std::time_t end_time = std::chrono::system_clock::to_time_t(end); //Convert to timestamp 
	std::time_t start_time = std::chrono::system_clock::to_time_t(start);
	std::ofstream LogFile;

	LogFile.open(l_filename,std::fstream::app); //Open the log file in append mode
	if(!LogFile.is_open()) //If an error occured when opening the file Exit the mode immediatly
	{ 
		system("pause");
		return (void)-1; //Stop the execution
	}
	std::cout << "Saving data to : " << l_filename <<  "..." << std::endl;
	std::ostringstream LogStream; //This is a string stream, it's used for generating a string that will be inserted into the log file
	char TimeStrStart[50], TimeStrEnd[50]; //2 char array which describe when the capture started and when it ended
	ctime_s(TimeStrStart, sizeof(TimeStrStart), &start_time); //Convert it to an readable format
	ctime_s(TimeStrEnd, sizeof(TimeStrEnd), &end_time);
	LogStream << "Started capture at " << TimeStrStart << "Took : " << elapsed_time.count() << " seconds and finished at " << TimeStrEnd << std::endl; //Display the moment where the capture started,ended and how much time we took
	std::string LogString = LogStream.str(); //Set the logstring to the string of the log stream
	LogFile.write(LogString.c_str(),LogString.length()); //Write into the file our string
	LogStream.str(""); //Clear the string stream 
	LogStream << "----BEGINNING OF THE CAPTURE----\n"; //Little message to display the beginning of the capture
	for (std::vector<Host>::iterator HostIt = Sniffer::gl_HostContainer.begin(); HostIt != Sniffer::gl_HostContainer.end(); HostIt++) //iterate through all the host
	{
		char IpAddress[16]; //String of an ip address
		snprintf(IpAddress, 16, "%d.%d.%d.%d", HostIt->GetIpAddress().byte1, HostIt->GetIpAddress().byte2, HostIt->GetIpAddress().byte3,HostIt->GetIpAddress().byte4); //Convert each host ip address to an readable format
		LogStream << IpAddress << " {\r\n"; //Insert to the stream something like that 192.168.1.0 { 
		for (auto const& PortIt : *HostIt->GetPortList()) { //Iterate through all the port of an hot
			LogStream << "\t" << PortIt.first << ":" << PortIt.second << std::endl; //Insert each port like this 80:http
		}
		LogStream << "}\r\n"; //End of Host port list
		LogString = LogStream.str(); //Convert an string stream to an string
		LogFile.write(LogString.c_str(), LogString.length()); //Write the string into the file
		LogStream.str(""); //Clear the stream
	}
	LogStream << "----END OF THE CAPTURE----\n"; //Little message to say that we finished our capture
	LogString = LogStream.str(); //Convert the stream to an string
	LogFile.write(LogString.c_str(),LogString.length()); //Write that string into the file
	LogStream.str(""); //Clear the stream
	LogFile.close(); //Close the file
	system("pause");

}
/*This function Capture the packet and decrypt it
 *It's used in pcap_loop()
 * It will interprate each packet
 *And print if it detected a new IP, or a new PORT
 */
void IPCaptureLoopBack(u_char*param,const struct pcap_pkthdr *header,const u_char *packet) {
	u_short src_port_pckt; //Source port 
	ip_address src_ip_addr_pckt; //Src IP address
	bool IsPortAlreadyDefined,IsAddressAlreadyDefined; //flag to know if an adress is already defined or if the port is already defined
	const unsigned char* src_ether_addr_pckt = nullptr; //Ethernet Source address
	bool IsSrcAnLocalIPAddress,IsDstAnLocalIpAddress,IsPortNotDefined; //Is the local ip address an Destination or Source address? + IsPortNotDefined
	Host* CurrentHost=nullptr; //Pointer to the current host we are editing


	/*Verify if the local ip address is the destination address or the  source address*/
	src_ip_addr_pckt = GetIpAddrFromPckt(packet + ETHER_HDR_LEN); //Get the IP address from the source
	if (src_ip_addr_pckt.byte1 == 192 && src_ip_addr_pckt.byte2 == 168) //if the first two bytes are equal to 192.168 (it mean the local ip address is the source one)
	{
		IsSrcAnLocalIPAddress = true; //set the flag to true
		src_port_pckt = GetPortFromPckt(packet + ETHER_HDR_LEN + IP_HDR_LEN); //If the local ip comes from source than get the port from the source
		src_ether_addr_pckt = GetEtherSrcAddr(packet); //same for the ethernet address
	}
	else
		IsSrcAnLocalIPAddress = false;

	/*Now let's try to get the destination address (IF THE SOURCE IP ADDRESS IS NOT THE LOCAL ONE)*/
	if (IsSrcAnLocalIPAddress == false) { 
		src_ip_addr_pckt = GetDestIpAddrFromPckt(packet + ETHER_HDR_LEN); //Get the Destination address
		if (src_ip_addr_pckt.byte1 == 192 && src_ip_addr_pckt.byte2 == 168) //If the destination address first two bytes are equal to 192.168
		{
			IsDstAnLocalIpAddress = true; //set the flag to true
			src_port_pckt = GetDestPortFromPckt(packet + ETHER_HDR_LEN + IP_HDR_LEN); //If the local ip comes from the destination than get the port from the destination
			src_ether_addr_pckt = GetDestEtherAddr(packet); //same for the ethernet address
		}
		else
			IsDstAnLocalIpAddress = false; //IT'S NOT AN DESTINATION ADDRESS
	}
	/*IF BOTH AREN'T AN LOCAL IP ADDRESS (OF CLASS C)*/
	if (IsSrcAnLocalIPAddress == false && IsDstAnLocalIpAddress == false) { 
		std::cout << "[X] WE ONLY SUPPORT C CLASS NETWORK, AN LOCAL IP ADDRESS SHOULD START BY 192.168\n";
		std::cout << " or there was just no local ip address on this packet\n";
		return;
	}
	/*Now verify if we can insert this element in our HostList*/
	IsAddressAlreadyDefined = Sniffer::DoesIPAddrExist(&src_ip_addr_pckt); //If in the Host Array there is already this Ip address it mean that we already inserted before this host
	if (IsAddressAlreadyDefined) {/*We can't insert a new host*/
		/*We must find where the IpAddress we are looking for is located in the std::vector<>*/
		for (std::vector<Host>::iterator HostIt = Sniffer::gl_HostContainer.begin(); HostIt != Sniffer::gl_HostContainer.end(); HostIt++) {
			if (src_ip_addr_pckt == (HostIt)->GetIpAddress()) { //If the ip address we found in the packet is equal to one of the host in our array
				CurrentHost = &(*HostIt); //We found the Host we were looking for 
				break; 
			}
		}
		/*Now that we had set up the pointer to the Desired Host we can "try" to insert a new port*/
		IsPortNotDefined = CurrentHost->AddNewPort(src_port_pckt,Sniffer::gl_famousPort); //Insert the new port if this port already exist it return false
		if (IsPortNotDefined) //If we manage to insert a port display that we inserted it
		{
			std::cout << "[+] New port detected : ";
			printf("%hu:", src_port_pckt);
			if (Sniffer::gl_famousPort->AllPortsNumber.find(src_port_pckt) == Sniffer::gl_famousPort->AllPortsNumber.end()) //Search if the founded port correspond in the famous port list
				std::cout << "TCP on : "; //if not the port name is equal to TCP 
			else 
				std::cout << Sniffer::gl_famousPort->AllPortsNumber[src_port_pckt] << " on : "; //IF yes print the name of the famous port
			printf("%d.%d.%d.%d\n", src_ip_addr_pckt.byte1, src_ip_addr_pckt.byte2, src_ip_addr_pckt.byte3, src_ip_addr_pckt.byte4); //and finally print the ip address where we found the new port
		}	
	}

	else { //In this case we never found before this Ip Address on the network
		//Display that we found a new Host
		std::cout << "[+] Found a New Ip Address on the network : " << std::endl;
		printf("%d.%d.%d.%d || ", src_ip_addr_pckt.byte1, src_ip_addr_pckt.byte2, src_ip_addr_pckt.byte3, src_ip_addr_pckt.byte4); //Display his ip address
		printf("%02x",src_ether_addr_pckt[0]); //Display  his MAC address
		for (int i = 1; i < ETHER_ADDR_LEN; i++)
			printf(":%02x",src_ether_addr_pckt[i]);
		printf("\n"); //endline

		Sniffer::gl_HostContainer.push_back(Host(src_ip_addr_pckt,src_ether_addr_pckt)); //Insert in our array the new IP address with his new port
			/*We must find where the IpAddress we are looking for is located in the std::vector<>*/
		for (std::vector<Host>::iterator HostIt = Sniffer::gl_HostContainer.begin(); HostIt != Sniffer::gl_HostContainer.end(); HostIt++) {
			if (src_ip_addr_pckt == (HostIt)->GetIpAddress()) { //If the IP address found in the packet is equal to the same IP address in the array
				CurrentHost = &(*HostIt); //set the current host to the one that we just found
				break;
			}
		}
		IsPortNotDefined = CurrentHost->AddNewPort(src_port_pckt, Sniffer::gl_famousPort); //Add a new port on the HOST
		if (IsPortNotDefined)
		{
			//And display that we inserted a new PORT
			std::cout << "[+] New port detected : ";
			printf("%hu:", htons(src_port_pckt));
			if (Sniffer::gl_famousPort->AllPortsNumber.find(src_port_pckt) == Sniffer::gl_famousPort->AllPortsNumber.end()) //Search if the founded port correspond in the famous port list
				std::cout << "TCP on : "; //if not the port name is equal to TCP 
			else
				std::cout << Sniffer::gl_famousPort->AllPortsNumber[src_port_pckt] << " on : "; //IF yes print the name of the famous port
			printf("%d.%d.%d.%d\n", src_ip_addr_pckt.byte1, src_ip_addr_pckt.byte2, src_ip_addr_pckt.byte3, src_ip_addr_pckt.byte4);
		}

	}
	

	Sniffer::SigManager(Sniffer::gl_currentSniffer,IpCapture); //Verify if we pressed CTRL-C
}
/*This function is the second option of the HOST CAPTURE mode
 *It just display all the data that we sniffed before
 *The sniffed data has been stored in an array called Sniffer::gl_HostContainer
 */
void Sniffer::DisplayHosts() {
	system("cls");
	if (Sniffer::gl_HostContainer.empty()) { //If no data was found
		std::cout << "[!] NO HOST HAVE BEEN SNIFFED PLEASE START AN CAPTURE BEFORE DISPLAYING HOST\n";
		system("pause");
		return (void)-1; //stop the execution
	}
	std::cout << "--- DISPLAY HOST CAPTURE ---\n";
	for (std::vector<Host>::iterator HostIt = Sniffer::gl_HostContainer.begin(); HostIt != Sniffer::gl_HostContainer.end(); HostIt++) //Iterate through each Host
	{
		HostIt->DisplayHost(*HostIt); //Display the Current Host
	}
	std::cout << "----END OF THE CAPTURE----\n";
	system("pause");
}
/*This simple function loop though the Host Array
 *If the same ip address that have been inserted in arguments
 *Have been found in the array return true
 *if not return false
 */
bool Sniffer::DoesIPAddrExist(ip_address* l_ip_addr) {
	bool AddrExist = false; //Flag that will be returned
	ip_address l_currentIp; //variable used to design an host by it's ip address in the loop
	/*FIRST BEFORE LOOPING THROUGH ALL THE CONTAINER VERIFY IF IT CONTAINS AT LEAST ONE VALUE!*/
	if (Sniffer::gl_HostContainer.empty()) { 
		AddrExist = false;
		return AddrExist;
	}
	//The array isn't empty, now we can verify if the ip address inserted in arguments have been found in the array
	for (int i = 0; i < Sniffer::gl_HostContainer.size(); i++) { //Loop through the array
		l_currentIp = Sniffer::gl_HostContainer.at(i).GetIpAddress(); //Set the variable to the ip address of the current host designed in the array
		if (l_currentIp == *l_ip_addr) { //If both IP are equal we can set the flag to true and exit the loop so as to return immediatly the flag
			AddrExist = true;
			break;
		}
		else { //Or they aren't equal continue to iterate
			AddrExist = false;
		}
	}
		
	return AddrExist; //Return the flag
}