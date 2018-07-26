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

bool GetNetvar(long processID, const char* table, const char* name, DWORD offset, DWORD& val)
{
	CNetVarManager nvMgr(processID);
	if (!nvMgr.Load())
		return false;
	val = nvMgr.GetNetVar(table, name) + offset;
	return true;
}