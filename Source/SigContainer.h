#pragma once
#ifndef SIGCONTAINER_H
#define SIGCONTAINER_H
/*Here we will contain all the signal state used for the SigManager*/
struct SigContainer {
	bool StupidDumpSig;
	bool DecryptDumpSig;
	bool StupidDumpFileSig;
	bool DecryptFileSig;
	bool UDPSnifferSig;
	bool DeviceStatSig;
	bool IpCaptureSig;
	
	SigContainer() {
		StupidDumpSig = DecryptDumpSig = StupidDumpFileSig = DecryptFileSig  = UDPSnifferSig = DeviceStatSig = IpCaptureSig = false; //Set all the flag to false (it mean we haven't pressed CTRL-C)
	}
};
/*FuncCode for the SigManager()*/
#define STUPID_DUMP  1
#define DECRYPT_DUMP 2
#define STUPID_DUMP_FILE 3
#define DECRYPT_DUMP_FILE 4
#define IpCapture 5
#define UDP_SNIFFER 6
#define DEVICE_STAT 7
/*                            */

#endif