#include "defs.h"
#include <windows.h> //Standard Windows Functions/Data Types
#include <iostream> //Constains Input/Output Functions (cin/cout etc..)
#include <TlHelp32.h> //Contains Read/Write Functions
#include <psapi.h>
#include <string> //Support For Strings
#include <sstream> //Supports Data Conversion
#include <vector>
#include "ProcMem.h"
#include "utils.h"

using namespace std;

ProcMem::ProcMem() 
{
	dwPID = 0;
	hProcess = nullptr;
	bProt = false;
}

ProcMem::ProcMem(DWORD processID)
{
	dwPID = 0;
	hProcess = nullptr;
	bProt = false;
	if(!Process(processID))
	{
		dwPID = 0;
		hProcess = nullptr;
	}
}

ProcMem::~ProcMem() 
{
	Free();
}

void ProcMem::Free()
{
	if (hProcess)
	{
		CloseHandle(hProcess);
		hProcess = nullptr;
		dwPID = 0;
	}
}

bool ProcMem::Process(DWORD processID) 
{
	if (hProcess)
		CloseHandle(hProcess);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, processID);
	if (hProcess)
	{
		dwPID = processID;
		return true;
	}
	else
		return false;
}

HANDLE _dumpModule(ProcMem* _this, const char* moduleName, std::vector<BYTE>& dumpOutput, DWORD dwPID)
{
	HANDLE module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID);
	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(moduleEntry);
	bool found = false;
	Module32First(module, &moduleEntry);
	do
	{
		if (iequals(moduleEntry.szModule, moduleName))
		{
			CloseHandle(module);
			found = true;
			break;
		}
	} while (Module32Next(module, &moduleEntry));

	if (!found)
		return nullptr;

	dumpOutput = std::vector<BYTE>(moduleEntry.modBaseSize);
	_this->ReadBinaryData((DWORD)moduleEntry.modBaseAddr, &dumpOutput[0], moduleEntry.modBaseSize, false);


	return moduleEntry.hModule;
}

bool CompareBytes(const unsigned char* bytes, const char* pattern)
{
	for (; *pattern; *pattern != ' ' ? ++bytes : bytes, ++pattern) 
	{
		if (*pattern == ' ' || *pattern == '?')
			continue;
		if (*bytes != getByte(pattern))
			return false;
		++pattern;
	}
	return true;
}

DWORD ProcMem::PatternScan(const char* moduleName, const char* pattern, const char* method, DWORD patternOffset, DWORD addressOffset)
{
	if (!hProcess)
		return 0;

	std::vector<BYTE> mod;
	auto hbase = _dumpModule(this, moduleName, mod, dwPID);
	if (!hbase)
		return 0;

	auto pb = &mod.at(0);
	auto max = mod.size() - 0x1000;

	for (auto off = 0UL; off < max; ++off)
	{
		if (CompareBytes(pb + off, pattern))
		{

			auto addr = DWORD(hbase) + off + patternOffset;

			if (iequals(method, "READ"))
				Read<DWORD>(addr, addr);

			if (iequals(method, "SUBSTRACT"))
				addr -= DWORD(hbase);

			if (iequals(method, "BOTH"))
			{
				Read<DWORD>(addr, addr);
				addr -= DWORD(hbase);
			}

			return addr + addressOffset;
		}
	}
	return 0;
}

DWORD ProcMem::Module(LPCSTR ModuleName) 
{
	if (!hProcess)
		return 0;

	HANDLE module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID);
	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(moduleEntry);
	Module32First(module, &moduleEntry);
	do
	{
		if (iequals(moduleEntry.szModule, ModuleName))
		{
			CloseHandle(module);
			return (DWORD)moduleEntry.modBaseAddr;
		}
	} while (Module32Next(module, &moduleEntry));
	CloseHandle(module);
	moduleEntry.modBaseAddr = 0;
	return (DWORD)moduleEntry.modBaseAddr;
}

DWORD ProcMem::GetBase()
{
	if (!hProcess)
		return 0;

	char pname[1024];
	GetProcessImageFileNameA(hProcess, pname, sizeof(pname));
	std::string sname = pname;
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID); 
	MODULEENTRY32 mEntry; 
	mEntry.dwSize = sizeof(mEntry);
	Module32First(hModule, &mEntry);
	CloseHandle(hModule);
	return (DWORD)mEntry.modBaseAddr;
}

size_t ProcMem::ReadDataAsStringA(DWORD addr, LPSTR dataBuffer, size_t sizeOfBuffer)
{
	if (!hProcess)
		return 0;

	Protection<void*>(addr, sizeOfBuffer);
	bool b = bool(ReadProcessMemory(hProcess, LPVOID(addr), dataBuffer, sizeOfBuffer, NULL));
	Protection<void*>(addr, sizeOfBuffer);
	if (!b)
		return 0;
	dataBuffer[sizeOfBuffer - 1] = '\0';
	return strlen(dataBuffer);
}

bool ProcMem::ReadBinaryData(DWORD addr, BYTE* dataBuffer, size_t sizeOfBufferAndBytesToRead, bool protect)
{
	if (!hProcess)
		return false;

	if (protect)
		Protection<void*>(addr, sizeOfBufferAndBytesToRead);
	bool b = bool(ReadProcessMemory(hProcess, LPVOID(addr), dataBuffer, sizeOfBufferAndBytesToRead, NULL));
	if (protect)
		Protection<void*>(addr, sizeOfBufferAndBytesToRead);

	return b;
}

bool ProcMem::WriteStringA(DWORD addr, const LPSTR dataBuffer)
{
	if (!hProcess)
		return false;

	size_t size = strlen(dataBuffer) + 1;
	Protection<void*>(addr, size);
	bool b = bool(WriteProcessMemory(hProcess, LPVOID(addr), dataBuffer, size, NULL));
	Protection<void*>(addr, size);

	return b;
}

bool ProcMem::WriteBinaryData(DWORD addr, const BYTE* dataBuffer, size_t size, bool protect)
{
	if (!hProcess)
		return false;

	if (protect)
		Protection<void*>(addr, size);
	bool b = bool(WriteProcessMemory(hProcess, LPVOID(addr), dataBuffer, size, NULL));
	if (protect)
		Protection<void*>(addr, size);

	return b;
}