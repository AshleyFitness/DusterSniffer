#include "ErrorHandler.h"
void ErrorHandler::fatal(const std::string& l_where, const std::string& l_errorstring) { //Just a simple function to show an error Message and exit the program
	std::cout << "Fatal Error Detected in : " << l_where << " Error : " << l_errorstring << std::endl;
	system("pause");
	std::exit(1); //We exited with an error
}
/*This function is basically the same comparing to fatal() but this one check if the devices are intialised*/
void ErrorHandler::pcap_fatal(const std::string& l_where, const std::string& l_errorstring, bool isDevices_init,pcap_if_t* ListDevices) {
	std::cout << "Fatal Error Detected in : " << l_where << " Error : " << l_errorstring << std::endl;
	if (isDevices_init)
		pcap_freealldevs(ListDevices);
	system("pause");
	std::exit(1); //We exited with an error
}
