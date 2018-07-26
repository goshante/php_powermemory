#pragma once


DWORD _getProcId(LPCSTR processName);
bool iequals(const char* _a, const char* _b);
bool GetNetvar(long processID, const char* table, const char* name, DWORD offset, DWORD& val);