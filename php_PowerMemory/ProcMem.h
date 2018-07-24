#ifndef PROCMEM_H //If Not Defined
#define PROCMEM_H //Define Now

#define WIN32_LEAN_AND_MEAN //Excludes Headers We Wont Use (Increase Compile Time)



class ProcMem
{
protected:

	//STORAGE
	HANDLE hProcess;
	DWORD dwPID, dwProtection;
	bool bProt;

	template <class cData>
	void Protection(DWORD dwAddress, size_t size = 0)
	{
		if (size == 0)
			size = sizeof(cData);
		if (!bProt)
			VirtualProtectEx(hProcess, (LPVOID)dwAddress, size, PAGE_READWRITE, &dwProtection); //Remove Read/Write Protection By Giving It New Permissions
		else
			VirtualProtectEx(hProcess, (LPVOID)dwAddress, size, dwProtection, &dwProtection); //Restore The Old Permissions After You Have Red The dwAddress

		bProt = !bProt;
	}

public:

	ProcMem();
	~ProcMem();

	template <class cData>
	cData Read(DWORD dwAddress)
	{
		if (!hProcess)
			return 0;
		cData cRead = 0; //Generic Variable To Store Data
		Protection<cData>(dwAddress);
		ReadProcessMemory(hProcess, (LPVOID)dwAddress, &cRead, sizeof(cData), NULL); 
		Protection<cData>(dwAddress);
		return cRead; //Returns Value At Specified dwAddress
	}

	template <class cData>
	void Write(DWORD dwAddress, cData cWrite)
	{
		if (!hProcess)
			return;
		Protection<cData>(dwAddress);
		WriteProcessMemory(hProcess, LPVOID(dwAddress), &cWrite, sizeof(cWrite), NULL);
		Protection<cData>(dwAddress);
	}

	size_t ReadDataAsStringA(DWORD addr, LPSTR dataBuffer, size_t sizeOfBuffer);
	void ReadBinaryData(DWORD addr, BYTE* dataBuffer, size_t sizeOfBufferAndBytesToRead, bool protect = true);

	void WriteStringA(DWORD addr, const LPSTR dataBuffer);
	void WriteBinaryData(DWORD addr, const BYTE* dataBuffer, size_t size, bool protect = true);

	//MEMORY FUNCTION PROTOTYPES
	virtual bool Process(DWORD processID); //Return Handle To The Process
	virtual DWORD GetBase();
	virtual DWORD PatternScan(const char* moduleName, const char* pattern, const char* method, DWORD patternOffset, DWORD addressOffset); //Find A Byte Pattern
	virtual DWORD Module(LPCSTR ModuleName); //Return Module Base Address
};
#endif


