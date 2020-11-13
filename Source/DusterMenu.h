#pragma once
#ifndef DUSTERMENU_H
#define DUSTERMENU_H
#include "Sniffer.h"
#include <array>
#include <fstream>
#include <Shlwapi.h>
/*DusterMenu is an simple class
  that handle the UI,manages SaveFile and allow the user to choose the modes and the device
  that he would like to use.
*/
class DusterMenu
{
public:
	DusterMenu();
	~DusterMenu();
	void DisplayTitle(); //Display DUSTERSNIFFER
	void ChooseAnDefaultDevice(Sniffer * l_sniffer); //Asking the user to choose an default device to use for sniffing the network
	void DisplayChoice(Sniffer *l_sniffer); //Display all the modes
	void SetSaveFiles(); //FileManager Menu
	void FUNOPTIONS(); // F U N MENU
	void ChangeTerminalColorSPECIALHACKERMODE(); //Change the terminal color (SPECIAL FUN MENU)
	void SETDEFAULTFOLDER(); //change the default file folder (SPECIAL FUN MENU)
	void ModifyFiles(int l_numMode);  //Modify an filename in m_FileList
	void DevNote(); //A little dev note
private:
	std::string m_DefaultFolder; //This string handle at the beginning "./" but can contain the folder entered in SETDEFAULTFOLDER()
	pcap_if_t* m_MainDevice; //Is an pointer to the Default Device choosed in CHooseAnDefaultDevice()
	std::array<std::string, 3> m_FileList; //All the 3 save files for the 3 modes
};
#endif