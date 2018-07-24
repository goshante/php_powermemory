#include "defs.h"
#include <windows.h> 
#include <TlHelp32.h> 
#include "utils.h"
#include <string>
#include "ProcMem.h"
#include "NetvarManager.h"

using namespace std;

DWORD _getProcId(LPCSTR processName)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)

		{
			if (_stricmp(entry.szExeFile, processName) == 0)
			{
				HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, false, entry.th32ProcessID);
				if (h)
				{
					return entry.th32ProcessID;
				}
				else
				{
					CloseHandle(snapshot);
					return 0;
				}
			}
		}
	}

	CloseHandle(snapshot);
	return 0;

}

bool iequals(const char* _a, const char* _b)
{
	string a(_a), b(_b);
	return std::equal(a.begin(), a.end(),
		b.begin(), b.end(),
		[](char a, char b) {
		return tolower(a) == tolower(b);
	});
}

DWORD GetNetvar(long processID, const char* table, const char* name, DWORD offset, bool& success)
{
	success = false;
	if (!pProcess->Attach(processID))
		return 0;

	if (!pNetVarManager->Load())
		return 0;

	DWORD val = 0;
	val = pNetVarManager->GetNetVar(table, name) + offset;
	pNetVarManager->Release();
	delete pNetVarManager;

	pProcess->Detach();
	delete pProcess;

	success = true;
	return val;
}