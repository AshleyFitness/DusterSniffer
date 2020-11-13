#include "DusterMenu.h"

DusterMenu::DusterMenu()  {
	/*Set the Console Size, (because if we dont do it the Title will be disgusting and ugly)*/
	HWND console = GetConsoleWindow(); 
	RECT windowSize;
	m_MainDevice = nullptr;
	GetWindowRect(console, &windowSize); 
	MoveWindow(console, windowSize.left, windowSize.top, 1150, 500, TRUE);
	//Set the default folder to ./
	m_DefaultFolder = "./";
} 
DusterMenu::~DusterMenu(){

}
void DusterMenu::DisplayTitle() {
	/*Simple Title*/
	std::cout << "/$$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$$$ /$$$$$$$$ /$$$$$$$         /$$$$$$  /$$   /$$ /$$$$$$ /$$$$$$$$ /$$$$$$$$ /$$$$$$$$ /$$$$$$$\n";
	std::cout << "| $$__  $$| $$  | $$ /$$__  $$|__  $$__/| $$_____/| $$__  $$       /$$__  $$| $$$ | $$|_  $$_/| $$_____/| $$_____/| $$_____/| $$__  $$\n";
	std::cout << "| $$  \\ $$| $$  | $$| $$  \\__/   | $$   | $$      | $$  \\ $$      | $$  \\__/| $$$$| $$  | $$  | $$      | $$      | $$      | $$  \\ $$\n";
	std::cout << "| $$  | $$| $$  | $$|  $$$$$$    | $$   | $$$$$   | $$$$$$$/      |  $$$$$$ | $$ $$ $$  | $$  | $$$$$   | $$$$$   | $$$$$   | $$$$$$$/\n";
	std::cout << "| $$  | $$| $$  | $$ \\____  $$   | $$   | $$__/   | $$__  $$       \\____  $$| $$  $$$$  | $$  | $$__/   | $$__/   | $$__/   | $$__  $$\n";
	std::cout << "| $$  | $$| $$  | $$ /$$  \\ $$   | $$   | $$      | $$  \\ $$       /$$  \\ $$| $$\\  $$$  | $$  | $$      | $$      | $$      | $$  \\ $$\n";
	std::cout << "| $$$$$$$/|  $$$$$$/|  $$$$$$/   | $$   | $$$$$$$$| $$  | $$      |  $$$$$$/| $$ \\  $$ /$$$$$$| $$      | $$      | $$$$$$$$| $$  | $$\n";
	std::cout << "|_______/  \\______/  \\______/    |__/   |________/|__/  |__/       \\______/ |__/  \\__/|______/|__/      |__/      |________/|__/  |__/\n";
	
}
void DusterMenu::ChooseAnDefaultDevice(Sniffer* l_sniffer) { /*We will ask the default device of the user and store it in our custom Sniffer class*/
	/*Those variables are a bunch of a flag and other stuff that will check if the input is valid, or that keep track if the device is working and we have some pointer too on the Devices List and on the device*/
	int choice = 0;
	int numOfDevices = l_sniffer->GetDeviceNumber();
	int i;
	bool isValid = false, isANumber;
	bool DevicesHasBeenChosed = false;
	pcap_if_t* pointerListDevices = l_sniffer->GetListDevices();
	pcap_if_t* pointerDevice = l_sniffer->GetDevice();
	std::string strChoice;
	if (numOfDevices == 0) /*Apparently NpCap Isn't installed we have to  quit!*/
		ErrorHandler::fatal("GetDeviceNumber()", "No interfaces found! Make Sure NpCap is installed.\n");
	while (!DevicesHasBeenChosed) /*As long we didn't choosed the Device we will keep asking the user to find any devices that he would like to use*/
	{
		isValid = false; //We reset this flag in case the Device isn't working so we can ask the user to choose another device
		for (pointerDevice = pointerListDevices; pointerDevice; pointerDevice = pointerDevice->next) //We display each device with the function Sniffer->DisplayDevices(pcap_if_t *Device);
			l_sniffer->DisplayDevices(pointerDevice);
		while (isValid == false) { /*While the chosen number is incorrect*/
			/*Here we are asking the user to choose an device*/
			std::cout << "-=-=-=-=-=-=-=-=-=-[ Choose An Default Device !]-=-=-=-=-=-=-=-=-=-\n";
			std::cout << "Please Choose an Device (1-" << numOfDevices << ") : ";
			std::cin >> strChoice;
			std::cin.clear();

			/*Golden Rule : Never Trust User Input!*/
			if (!strChoice.empty() && std::all_of(strChoice.begin(), strChoice.end(), ::isdigit))
			{
				choice = atoi(strChoice.c_str());
				if ((choice < 1) || (choice > numOfDevices))
					std::cout << "[!!] Invalid Choice! Please Make sure to choose a number between 1 and " << numOfDevices << ".\n"; /*This devices doesn't exist*/
				else
					isValid = true;
			}
			else
				std::cout << "Invalid Number Provided!\n"; /*Wrong Data type*/
		}


		/* Jump to the selected adapter*/
		for (pointerDevice = pointerListDevices, i = 0; i < choice; pointerDevice = pointerDevice->next, i++)
			m_MainDevice = pointerDevice; /*The main device is now the device that have been chosen!*/
		/*Checking if the adapter is working or not....*/

		//Asking the user if he want to test his device
		std::string inputResult;
		std::cout << "Would you like to test if the Device is working ? (y/n) : ";
		std::cin >> inputResult;
		std::cin.clear();

		bool DeviceWorking; //An flag that will get the value of the Function IsDeviceWorking()
		if (inputResult == "y") { //If we wanna test it than we are making a bunch of test
			DeviceWorking = l_sniffer->IsDeviceWorking(m_MainDevice); //Custom function that return a boolean if it's working or not
			if (DeviceWorking == false) 
			{
				//If it's not working we can ask the user if he would like to change his device
				std::cout << "Apparently this device cannot sniff any packet would you like to still use it or choose another device ? (y/n) : ";
				std::string chooseAnotherDevice;
				std::cin >> chooseAnotherDevice;
				std::cin.clear();
				if (chooseAnotherDevice == "y") //The user still want to use it
				{
					DevicesHasBeenChosed = true;
				}
				else if(chooseAnotherDevice == "n") {
					DevicesHasBeenChosed = false;
				}
				else {
					std::cout << "[!]Warning you choosed an invalid option, Setting the option to no...\n";
				}
			}
			else {
				//The device is Working!
				std::cout << "Apparently this device is able to sniff some packet, Have fun using DusterSniffer!\n";
				DevicesHasBeenChosed = true;
			}
		}
		else {
			//We dont want to test the device.
			std::cout << "Okay,No problem Have fun using DusterSniffer!\n";
			DevicesHasBeenChosed = true;
		}

	}

	std::cout << "\nThe devices that have been chosed is : " <<m_MainDevice->description << std::endl;
	system("pause");
}
/*This is the main Function of this class, this function is the one that will show the menu and attribute an function to the selection of the user
 *If Someone have a new idea of option that we can add in this program feel free to send me an message!*/
void DusterMenu::DisplayChoice(Sniffer* l_sniffer) {
	bool Exit = false; 
	while (!Exit) { //Infinite loop until we choose 11
		system("cls"); //We start by cleaning the console...
		std::cout << "{*}{*}{*}{*}{*}{*}{*}{*}{*} [ =-= Duster Sniffer Menu =-= ] {*}{*}{*}{*}{*}{*}{*}{*}{*}\n";
		std::cout << "1)\tStupid Dump.\n";
		std::cout << "2)\tDecrypt Dump.\n";
		std::cout << "3)\tStupid Dump a file.\n";
		std::cout << "4)\tDecrypt a file.\n";
		std::cout << "5)\tSniff UDP packets.\n";
		std::cout << "6)\tDevice Statistics.\n";
		std::cout << "7)\tGet IP Addresses.\n";
		std::cout << "8)\tSet a Save File.\n";
		std::cout << "9)\tChange Device.\n";
		std::cout << "10)\tF  U  N    O  P  T  I  O  N.\n";
		std::cout << "11)\tExit\n";
		std::cout << "Enter Your selection : ";
		//Always create an string when receiving an input and convert it after to an integer
		std::string strDesiredMode; 
		int DesiredMode;
		bool isAValidOption = false;

		while (!isAValidOption) { //While the User Input isn't valid continue to ask for input
			std::cin >> strDesiredMode;
			std::cin.clear();
			if (!strDesiredMode.empty() && std::all_of(strDesiredMode.begin(), strDesiredMode.end(), ::isdigit)) //IF THE USER ENTERED NUMBERS
			{
				DesiredMode = atoi(strDesiredMode.c_str()); //we can convert it to an integer
				if ((DesiredMode < 1) || (DesiredMode > 11)) //Now verify that integer is btw 1 and 11
					std::cout << "[!!] Invalid Choice! Please Make sure to choose a number between 1 and 11.\n"; /*This option doesn't  exist*/
				else
					isAValidOption = true;
			}
			else
				std::cout << "Invalid Number Provided!\n"; /*Wrong Data type*/
		}
		switch (DesiredMode) {//Switch statement that associate each number to an function
 		case 1:
			l_sniffer->StupidDump(m_MainDevice,m_FileList.at(0));
			break;
		case 2:
			l_sniffer->DecryptDump(m_MainDevice,m_FileList.at(1));
			break;
		case 3:
			l_sniffer->StupidDumpFile(m_DefaultFolder);
			break;
		case 4:
			l_sniffer->DecryptDumpFile(m_DefaultFolder);
			break;
		case 5:
			l_sniffer->SniffUdpPackets(m_MainDevice);
			break;
		case 6:
			l_sniffer->Statistics(m_MainDevice);
			break;
		case 7:
			l_sniffer->IpCaptureSniff(m_MainDevice,m_FileList.at(2));
			break;
		case 8:
			SetSaveFiles();
			break;
		case 9: 
			ChooseAnDefaultDevice(l_sniffer);
			break;
		case 10:
			FUNOPTIONS();
			break;
		case 11:
			std::cout << "Thanks for using DusterSniffer,feel free to come back later!\n";
			system("pause");
			Exit = true;
			break;
		}
	}
}
/*This function display all Save Files that have been set.
  But it can be used as well to defines some save files
  */
void DusterMenu::SetSaveFiles() {
	system("cls");
	int i = 0; 
	std::cout << "\tS  A  V  E		F  I  L  E\n";
	std::cout << "Welcome to the files manager, this mode is really simple it lets you defines some files\n";
	std::cout << "where you be able to store all of your traffic dump\n";
	std::cout << "[?] How does it work?, well it's really simple you have 3 modes where each modes can be associated with a file\n";
	std::cout << "[!] FILES ARE LOCATED IN THE CaptureLogs folder\n";
	std::cout << "Here is the following files that have been defined : \n";
	for (std::array<std::string, 3>::iterator FileIt = m_FileList.begin(); FileIt != m_FileList.end(); FileIt++) { //Iterate through our array of Files

		switch (i) {
		case 0:
			std::cout << "Stupid Dump : ";
			break;
		case 1:
			std::cout << "Decrypt Dump : ";
			break;
		case 2:
			std::cout << "Host Sniffer : ";
			break;
		}
		if ((*FileIt).empty()) { //If the file isn't define than we display that it is not
			std::cout << "FILE ISN'T DEFINED";

		}
		else //Or display the filename
			std::cout << (*FileIt);
		std::cout << std::endl; //and finish by an end line
		i++; //incrementing by one for the swith(i) statement
	}
	
	std::cout << "Select a file that you wish to modify (1-3) : ";
	int FileChoice;
	std::string strFileChoice;
	bool isAValidChoice = false;
	while (!isAValidChoice) { //Never trust user input
		std::cin >> strFileChoice;
		std::cin.ignore();
		try {
			FileChoice = std::stof(strFileChoice); //try to convert  if not we throw and catch the error
			if (FileChoice < 1 || FileChoice > 3) {
				std::cout << "[!] ERROR : Please make sure your choice is between 1 and 3\n";
			}
				else {
					isAValidChoice = true;
				}
		}
		catch (...) {
			std::cout << "Invalid Number Provided!\n"; //Wrong datatype
		}
	}
	system("pause");
	ModifyFiles(FileChoice); //Now we can modify the selected file
	system("pause");
}
void DusterMenu::ModifyFiles(int l_numMode) {
	CreateDirectory("CaptureLogs", NULL); //If the directory was not created we create CaptureLogs
	system("cls");
	bool IsFileUsable = false; //Is the file Valid?
	std::string fileName;
	l_numMode -= 1; //The array start by 0 so if we choosed 1 for example we have to set it to 0 
	std::cout << "Welcome, to the file manager!\n";
	std::cout << "Here you can define an filename where you would like to save capture data\n";
	std::cout << "[?] You don't have to precise a file format file like .txt just put for example <ThisIsAFileName>\n";
	std::cout << "[??] If the file doesn't exist we will create a new one!\n";
	while (!IsFileUsable) { //While the file is not valid

		std::cout << "Enter a filename : ";
		std::cin >> fileName;
		std::cin.ignore();
		if(l_numMode != 2) //If it's the first 2 options the extension will be .pcap
		fileName.append(".pcap"); //We add .pcap for the extension
		else
			fileName.append(".log"); //and for the last option it will be an .log file

		fileName.insert(0, "CaptureLogs/"); //Insert at the beginning of the string the directory name
		if (PathFileExists(fileName.c_str()) == TRUE) { //Verify if the file already exist 
			int returnVal; //flag of the _access function

			if (returnVal = _access(fileName.c_str(), 06) != EACCES) { //Let's verify if we have access to the file
				IsFileUsable = true; //if we have access we can leave the loop
			}
				else {
					std::cout << "[!!] CAN'T READ OR WRITE ON THE FILE\n";
					return (void)-1; //At this point leave the function
				}
			if (IsFileUsable) { //Display an message, that this file already exist so we can use it instead of creating a new one
				std::cout << "[...] File exist we can use it to store content inside.\n";
			}
		}
		else {
			std::ofstream NewFile(fileName.c_str()); //We create the file
			NewFile.close();  //We don't need it anymore
			/*Let's imagine that the user used character like <> /\ ? which are invalid charactes or if the filename is con for example (con is an invalid filename on windows)
			on windows let's verify that the file have been created if not ask again the user to enter a filename*/
			if (PathFileExists(fileName.c_str()) == FALSE) { //If the file hasn't been created it mean we used invalid character (or this PC has really weird permissions)
				std::cout << "[!] Invalid Characters have been used, Use another file name please!\n";

			}
			else { //Finally we created the file we can now leave the loop
				std::cout << "[+] New file created : " << fileName << std::endl;
				IsFileUsable = true;
			}
		}
	}
	//After veryfing everything is safe, we can finally  insert the filename into the array
	m_FileList[l_numMode] = fileName;
	std::cout << "The following file that have been selected is : " << fileName << std::endl;
}
/*LITTLE BONUS MENU that i made for fun
  It's not really important tbh but it allow cool feature like changing terminal color or set the default folder to something else than ./
*/
void DusterMenu::FUNOPTIONS() {
	bool Continue = true;
	while (Continue) {
		system("cls");
		std::cout << "[[[]]]...| WELCOME TO FUN PLACE :DDDD |...[[[]]]\n";
		std::cout << "(THIS IS A SMALL LITTLE MENU FOR F	U	N)\n";
		std::cout << "1) CHANGE TERMINAL COLOR H3XXER\n";
		std::cout << "2) WHO CREATED THIS????????\n";
		std::cout << "3)  OR WOULD YOU LIKE TO SET  THE DEFAULT FOLDER\n";
		std::cout << "4) COME BACK TO \"NORMAL MENU\"\n";
		std::string strDesiredMode;
		int DesiredMode;
		bool isAValidOption = false;

		while (!isAValidOption) { //similar source  code from the "Normal menu"
			std::cin >> strDesiredMode;
			std::cin.clear();
			if (!strDesiredMode.empty() && std::all_of(strDesiredMode.begin(), strDesiredMode.end(), ::isdigit))
			{
				DesiredMode = atoi(strDesiredMode.c_str());
				if ((DesiredMode < 1) || (DesiredMode > 4))
					std::cout << "[!!] Invalid Choice! Please Make sure to choose a number between 1 and 4.\n"; /*This option doesn't  exist*/
				else
					isAValidOption = true;
			}
			else
				std::cout << "Invalid Number Provided!\n"; /*Wrong Data type*/
		}
		switch (DesiredMode) {
		case 1:
			ChangeTerminalColorSPECIALHACKERMODE();
			break;
		case 2:
			DevNote();
			break;
		case 3:
			SETDEFAULTFOLDER();
			break;
		case 4:
			Continue = false;
			break;
		}
	}
	}
/*Cool feature that allow the user to change his terminal color*/
void DusterMenu::ChangeTerminalColorSPECIALHACKERMODE() {
	//Display the title
	system("cls");
	std::cout << "[\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\] H33XER T3RM1N@L C0NF1G P@N3L [///////////////////////////////////////////////]\n";
	std::cout << "H3R U C@N S3T UP S0M C00L 0PTI0NS FOR Y0UR T3RMINAL\n";
	std::cout << "H3r @re th3 f0low1ng C0l0rs that have b33n add3d for this program\n";
	
	//We need to get an Handle of the Console so as to modify it
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	// Display all colors avalaible for the console
	for (int i = 1; i < 16; i++)
	{
		// pick the colorattribute k you want
		SetConsoleTextAttribute(hConsole, i);
		std::cout << i << " DusterSniffer is F\tU\tN" << std::endl; //Display the color number with an sample text
	}
	SetConsoleTextAttribute(hConsole, 7); //Re set the console the default color
	std::cout << "Select the color you would like to choose : ";
	std::string strColor;
	int Color;
	bool isAValidOption = false;
	 
	while (!isAValidOption) {//Verify that the color is btw 1 and 15 and that it's a number
		std::cin >> strColor;
		std::cin.clear();
		if (!strColor.empty() && std::all_of(strColor.begin(), strColor.end(), ::isdigit)) 
		{
			Color = atoi(strColor.c_str());
			if ((Color < 1) || (Color > 15))
				std::cout << "[!!] Invalid Choice! Please Make sure to choose a number between 1 and 15.\n"; /*This option doesn't  exist*/
			else
				isAValidOption = true;
		}
		else
			std::cout << "Invalid Number Provided!\n"; /*Wrong Data type*/
	}
	SetConsoleTextAttribute(hConsole, Color); //set the new color fo the terminal
	std::cout << " YAY : 3 ENJ0Y Y0UR N3WWWWWWWWWWWWW C0L0R !\n";
	system("pause");
}
/*This function allow the user to change his Foldername by default it's the same where is located the program aka : "./" */
void DusterMenu::SETDEFAULTFOLDER() {
	//Display Title
	system("cls");
	std::cout << ">...>...>... FOLDER MANAGER ...<...<...<\n";
	std::cout << "Welcome to the folder manager, This mode is one of the \"Bonus\" mode\n";
	std::cout << "You must know that when, you use Dump Stupid File mode and Decrypt File mode\n";
	std::cout << "The program is searching the file that you've entered in the same directory where's the program is located.\n";
	std::cout << "So if you are too lazy to copy the file in to the same directory we have created this aMAZING mode\n";
	std::cout << "If you have a folder that is in the same directory just write \"DirectoryName\" n";
	std::cout << "Or if you want to precise the whole path you can write it Like that  C:/DirectoryName/AnotherDirectoryName\n";
	//Ask for input
	std::string FolderName;
	std::cin >> FolderName;
	std::cin.ignore();
	//We need to get some stat about the folder that have been entered
	DWORD IsFolderExistant = GetFileAttributes(FolderName.c_str());
	if (IsFolderExistant == INVALID_FILE_ATTRIBUTES)  //If this directory doesn't exist
		std::cout << "This directory doesn't exist!\n";
	if (IsFolderExistant & FILE_ATTRIBUTE_DIRECTORY) { //If it's an Directory
		FolderName.append("/"); //Insert the little "/" because it's an directory not an file
		m_DefaultFolder = FolderName; //set the m_defaultfolder to the new folder name
		std::cout << "The Default Folder is set to : " << FolderName << std::endl; 
	}
	else { //It's probably a file
		std::cout << "This is not an directory\n!";
	}

	system("pause");
}
void DusterMenu::DevNote() {
	system("cls");
	std::cout << "Hi! Thanks for reading this\n";
	std::cout << "Firstly i would like to thank you for using my software.\n";
	std::cout << "I would really enjoy if you could share this software with other people.\n";
	std::cout << "DusterSniffer is an OpenSource Project it mean you can check the source code on Github\n";
	std::cout << "At this Address : https://github.com/AshleyFitness \n";
	std::cout << "Secondly, If you have any bug to report or any suggestion for this program i would really appreciate\n";
	std::cout << "If you could send to me your request on GitHub\n";
	std::cout << "Feel free to contribute to the source code!\n";
	std::cout << "\n\n\nHAVE FUN USING DUSTERSNIFFER!\n";
	system("pause");
}