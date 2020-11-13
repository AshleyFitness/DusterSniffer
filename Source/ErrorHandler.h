#pragma once
#ifndef ERROR_HANDLER
#define ERROR_HANDLER
#include <exception>
#include <string>
#include <sstream>
#include <iostream>
#include "pcap.h"
//Just a simple class that is used for exiting the program in case of an Fatal error
class ErrorHandler
{
public:
	ErrorHandler() {};
	~ErrorHandler() {};
	static void fatal(const std::string& l_where,const std::string& l_errstring); //Fatal error in C++
	static void pcap_fatal(const std::string& l_where, const std::string& l_errstring,bool isDevices_init,pcap_if_t* listDevices); //Fatal error in the pcap library
	
private:
};
#endif