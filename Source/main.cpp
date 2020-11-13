/* /$$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$$$ /$$$$$$$$ /$$$$$$$         /$$$$$$  /$$   /$$ /$$$$$$ /$$$$$$$$ /$$$$$$$$ /$$$$$$$$ /$$$$$$$ 
| $$__  $$| $$  | $$ /$$__  $$|__  $$__/| $$_____/| $$__  $$       /$$__  $$| $$$ | $$|_  $$_/| $$_____/| $$_____/| $$_____/| $$__  $$
| $$  \ $$| $$  | $$| $$  \__/   | $$   | $$      | $$  \ $$      | $$  \__/| $$$$| $$  | $$  | $$      | $$      | $$      | $$  \ $$
| $$  | $$| $$  | $$|  $$$$$$    | $$   | $$$$$   | $$$$$$$/      |  $$$$$$ | $$ $$ $$  | $$  | $$$$$   | $$$$$   | $$$$$   | $$$$$$$/
| $$  | $$| $$  | $$ \____  $$   | $$   | $$__/   | $$__  $$       \____  $$| $$  $$$$  | $$  | $$__/   | $$__/   | $$__/   | $$__  $$
| $$  | $$| $$  | $$ /$$  \ $$   | $$   | $$      | $$  \ $$       /$$  \ $$| $$\  $$$  | $$  | $$      | $$      | $$      | $$  \ $$
| $$$$$$$/|  $$$$$$/|  $$$$$$/   | $$   | $$$$$$$$| $$  | $$      |  $$$$$$/| $$ \  $$ /$$$$$$| $$      | $$      | $$$$$$$$| $$  | $$
|_______/  \______/  \______/    |__/   |________/|__/  |__/       \______/ |__/  \__/|______/|__/      |__/      |________/|__/  |__/*/


/********************************An OpenSource Project by Dusterito*******************************/
/*[!] You can modify this program as much as you want but please don't remove this message!*
 * If you Notice some bugs, or find ways to upgrade the source code feel free to send me a message on GitHub.
	DusterSniffer 2020-2021
 */

//Dependencies NPCAP from https://nmap.org/npcap/ from the Nmap Project (A remaster of the Old WinPcap library)  
//Also check the Windows API 

#include "DusterMenu.h"
#pragma comment( lib, "shlwapi.lib") 
int main(int argc,char *argv[]) {
	DusterMenu * Menu = new DusterMenu(); //This Object is simply handling the Device Choice and Mode choice
	Menu->DisplayTitle();
	Sniffer* DusterSnifferObj = new Sniffer();
	DusterSnifferObj->InitDevices(); //This function simply Initialises the device list
	Menu->ChooseAnDefaultDevice(DusterSnifferObj); //Choose an default device
	Menu->DisplayChoice(DusterSnifferObj); //Display all the modes (INFINITE LOOP)
	return 0;
}