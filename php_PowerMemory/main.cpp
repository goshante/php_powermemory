#include "defs.h"
#include "zend_config.w32.h" 
#include "php.h"
#include "SimpleString.h"
#include "winapi_php.h"
#include "utils.h"
#include "ProcMem.h"


PHP_FUNCTION(PowerMem_Help);
PHP_FUNCTION(PowerMem_About);
PHP_FUNCTION(PowerMem_MessageBox);
PHP_FUNCTION(PowerMem_GetProcessID);

PHP_FUNCTION(PowerMem_ReadProcessMemory);

PHP_FUNCTION(PowerMem_WriteProcessMemoryLong);
PHP_FUNCTION(PowerMem_WriteProcessMemoryDword);
PHP_FUNCTION(PowerMem_WriteProcessMemoryFloat);
PHP_FUNCTION(PowerMem_WriteProcessMemoryDouble);
PHP_FUNCTION(PowerMem_WriteProcessMemoryBool);
PHP_FUNCTION(PowerMem_WriteProcessMemoryByte);
PHP_FUNCTION(PowerMem_WriteProcessMemoryChar);
PHP_FUNCTION(PowerMem_WriteProcessMemoryString);
PHP_FUNCTION(PowerMem_WriteProcessMemoryBytes);

PHP_FUNCTION(PowerMem_PatternScan);
PHP_FUNCTION(PowerMem_SRC_GetNetVarOffset);

PHP_FUNCTION(PowerMem_ShellExecute);

#define PowerMemoryVersion	"1.1"

const zend_function_entry PowerMemory_functions[] = 
	{
		PHP_FE(PowerMem_Help, NULL)
		PHP_FE(PowerMem_About, NULL)
		PHP_FE(PowerMem_MessageBox, NULL)
		PHP_FE(PowerMem_GetProcessID, NULL)

		PHP_FE(PowerMem_ReadProcessMemory, NULL)

		PHP_FE(PowerMem_WriteProcessMemoryLong, NULL)
		PHP_FE(PowerMem_WriteProcessMemoryDword, NULL)
		PHP_FE(PowerMem_WriteProcessMemoryFloat, NULL)
		PHP_FE(PowerMem_WriteProcessMemoryDouble, NULL)
		PHP_FE(PowerMem_WriteProcessMemoryBool, NULL)
		PHP_FE(PowerMem_WriteProcessMemoryByte, NULL)
		PHP_FE(PowerMem_WriteProcessMemoryChar, NULL)
		PHP_FE(PowerMem_WriteProcessMemoryString, NULL)
		PHP_FE(PowerMem_WriteProcessMemoryBytes, NULL)

		PHP_FE(PowerMem_PatternScan, NULL)
		PHP_FE(PowerMem_SRC_GetNetVarOffset, NULL)

		PHP_FE(PowerMem_ShellExecute, NULL)
		PHP_FE_END      
	};

zend_module_entry PowerMemory_module_entry =
{
	STANDARD_MODULE_HEADER,       // #if ZEND_MODULE_API_NO >= 20010901
	"PowerMemory",                // Module name
	PowerMemory_functions,        // Exported functions
	NULL,                         // PHP_MINIT(test), Module Initialization
	NULL,                         // PHP_MSHUTDOWN(test), Module Shutdown
	NULL,                         // PHP_RINIT(test), Request Initialization
	NULL,                         // PHP_RSHUTDOWN(test), Request Shutdown
	NULL,                         // PHP_MINFO(test), Module Info (для phpinfo())
	PowerMemoryVersion,           // Module version
	STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(PowerMemory)


PHP_FUNCTION(PowerMem_Help)
{
	const char pmhlp[] = 
	{ 
		"PHP PowerMemory interface provides following functions:\n\n\n" 
		"PowerMem_About() - returns string. Information about PHP PowerMemory release.\n\n" 
		"PowerMem_MessageBox(string Message, string Title) - returns nothing. Calls default message box of MS Windows.\n\n" 
		"PowerMem_GetProcessID(string processName) - returns id of found process (int). Returns 0 if process not found.\n\n"
		"PowerMem_ReadProcessMemory(long ProcessID, string moduleName, string offset, string readAs, long bytes_num, bool returnAddress) - returns read data. Reads data in process with specific id.\n"
		" moduleName - Takes name of any base module to make base reading address as base address of this module. If module name is 'BASE' it will be base address of process. If 'NULL' - the address will be 0. If moduleName is string hex number (\"0x...\") than base address will be this value. This parameter can accept the return values of this function of types 'dword' and 'pointer'\n"
		" offset - accepts offset from base address. It can be both string or int format. Hex of decimal. Can be 0.\n"
		" readAs - determines what type the function should read and return. Available types: 'bytes' (number of bytes is choosen by caller), 'byte', 'dword', 'pointer', 'int', 'long', 'float', 'double', 'bool', 'char', 'string' (max number of chars is choosen by caller)\n"
		" bytes_num - it matters only when 'bytes' or 'string' type was selected. Determines how much bytes we need to read or maximum number of chars for string.\n"
		" returnAddress - if 'false' function will work in normal mode. Will read value by input address and return it. If 'true' function will never read value, just return address of it (base + offset)\n\n"
		"PowerMem_WriteProcessMemoryLong(long ProcessID, string moduleName, string offset, long value)\n"
		"PowerMem_WriteProcessMemoryDword(long ProcessID, string moduleName, string offset, string value)\n"
		"PowerMem_WriteProcessMemoryFloat(long ProcessID, string moduleName, string offset, float value)\n"
		"PowerMem_WriteProcessMemoryDouble(long ProcessID, string moduleName, string offset, double value)\n"
		"PowerMem_WriteProcessMemoryBool(long ProcessID, string moduleName, string offset, bool value)\n"
		"PowerMem_WriteProcessMemoryByte(long ProcessID, string moduleName, string offset, string value)\n"
		"PowerMem_WriteProcessMemoryChar(long ProcessID, string moduleName, string offset, string value)\n"
		"PowerMem_WriteProcessMemoryString(long ProcessID, string moduleName, string offset, string value)\n"
		"PowerMem_WriteProcessMemoryBytes(long ProcessID, string moduleName, string offset, array value) - Returns nothing. all this function are writing value to memory of process. First 3 parameters are the same as in PowerMem_ReadProcessMemory.\n"
		" value - Depends on it's type. If byte or dword it is string with hex (or decimal) value of it. If char - it should be string with only 1 character. If bytes - it should be array of ints or strings with hex values.\n\n"
		"PowerMem_ShellExecute(string operation, string file, string parameters, string directory, long nShowCmd) - Returns nothing. Same as Windows ShellExecute().\n\n"
		"PowerMem_PatternScan(long ProcessID, string module, string pattern, string method, string patternOffset, string addrOffset) - Returns hex value in string (DWORD). Scans memory by IDA-like signature pattern and returns scanned value.\n"
		" module - Name of module to search.\n"
		" pattern - IDA-like byte pattern.\n"
		" patternOffset - hex or decimal value, offset of pattern.\n"
		" addrOffset - hex or decimal value, offset of found address.\n\n"
		"PowerMem_SRC_GetNetVarOffset(long processID, string tableName, string varName, string offset) - Returns hex value in string (DWORD). Special function for finding offset of Source Engine's netvar offsets.\n"
		" tableName - Name of netvar's table to search.\n"
		" varName - name of netvar.\n"
		" offset - offset added to netvar. Can be 0. String hex or decimal long.\n"
	};
	RETURN_STRING(pmhlp, 1);
}

PHP_FUNCTION(PowerMem_About)	//No args
{
	String str = "PowerMemory PHP extension by Fullmetal Alcoholic, version ";
	str.Append(PowerMemoryVersion);
	RETURN_STRING(str.c_str(), 1);  
}

PHP_FUNCTION(PowerMem_MessageBox)
{
	char* message, *title;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &message, &length, &title, &length) == FAILURE)
		return;

	MessageBoxA(NULL, message, title, MB_OK);
	RETURN_NULL();
}

PHP_FUNCTION(PowerMem_GetProcessID)	//(string processName)
{
	char* processName;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &processName, &length) == FAILURE)
		return;
	
	if (length == 0)
	{
		RETURN_LONG(0);
	}
	else
	{
		RETURN_LONG(_getProcId(processName));
	}
}

void EnableDebugPrivilege(bool fEnable)
{
	HANDLE hToken;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL);
		CloseHandle(hToken);
	}
}

PHP_FUNCTION(PowerMem_ReadProcessMemory) //(long ProcessID, string moduleName, string offset, string readAs, long bytes_num, returnAddress)
{
	long ProcessID, bytes_num;
	bool returnAddress;
	char *moduleName, *offset, *readAs;
	int moduleName_len, offset_len, readAs_len;
	ProcMem mem;
#ifdef _DEBUG
	MessageBoxA(NULL, "Attach debugger to php.exe and click OK...", "Debug", MB_OK);
#endif
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s|s|s|l|b", &ProcessID, &moduleName, &moduleName_len, &offset, &offset_len, &readAs, &readAs_len, &bytes_num, &returnAddress) == FAILURE)
		return;

	if (ProcessID <= 0)
	{
		RETURN_STRING("Error: Process ID cannot be zero or lower than zero.", 1);
	}

	if (moduleName_len == 0)
	{
		RETURN_STRING("Error: Module name is empty.", 1);
	}

	if (readAs_len == 0)
	{
		RETURN_STRING("Error: Input type is empty.", 1);
	}

	if (!mem.Process(ProcessID))
	{
		RETURN_STRING("Error: Process not found.", 1);
	}

	DWORD base, dwOffset, addr;
	char* tmp;

	if (moduleName_len > 2 && moduleName[0] == '0' && (moduleName[1] == 'x' || moduleName[1] == 'X'))
		base = strtoul(moduleName, &tmp, 16);
	else
	{
		if (strcmp(moduleName, "BASE") == 0)
			base = mem.GetBase();
		else if (strcmp(moduleName, "NULL") == 0)
			base = 0;
		else
			base = mem.Module(moduleName);
	}

	if (offset_len == 0)
		dwOffset = 0;
	else if (offset_len > 2 && offset[0] == '0' && (offset[1] == 'x' || offset[1] == 'X'))
		dwOffset = strtoul(offset, &tmp, 16);
	else
		dwOffset = strtoul(offset, &tmp, 10);

	addr = base + dwOffset;

	if (returnAddress)
	{
		char zdw[32];
		sprintf_s(zdw, 32, "0x%X", addr);
		RETURN_STRING(zdw, 1);
	}

	EnableDebugPrivilege(true);
	if (iequals(readAs, "bytes"))
	{
		if (bytes_num <= 0)
		{
			RETURN_STRING("Error: Cannot read 0 bytes.", 1);
		}
		BYTE* b_arr = new BYTE[bytes_num];
		mem.ReadBinaryData(addr, b_arr, bytes_num);
		array_init(return_value);
		for (int i = 0; i < bytes_num; i++)
			add_index_long(return_value, i, b_arr[i]);
		return;
	}
	else if (iequals(readAs, "dword") || iequals(readAs, "pointer"))
	{
		DWORD dw = 0;
		if (!mem.Read<DWORD>(addr, dw))
		{
			RETURN_STRING("Error: Read operation failed.", 1);
		}
		char zdw[32];
		sprintf_s(zdw, 32, "0x%X", dw);
		RETURN_STRING(zdw, 1);
	}
	else if (iequals(readAs, "float"))
	{
		float fl = .0f;
		if (mem.Read<float>(addr, fl))
		{
			RETURN_DOUBLE(fl);
		}
		else
		{
			RETURN_STRING("Error: Read operation failed.", 1);
		}
	}
	else if (iequals(readAs, "double"))
	{
		double dou = .0;
		if (mem.Read<double>(addr, dou))
		{
			RETURN_DOUBLE(dou);
		}
		else
		{
			RETURN_STRING("Error: Read operation failed.", 1);
		}
	}
	else if (iequals(readAs, "bool"))
	{
		bool b = false;
		if (mem.Read<bool>(addr, b))
		{
			RETURN_BOOL(b);
		}
		else
		{
			RETURN_STRING("Error: Read operation failed.", 1);
		}
	}
	else if (iequals(readAs, "char"))
	{
		char c = '\0';
		if (!mem.Read<char>(addr, c))
		{
			RETURN_STRING("Error: Read operation failed.", 1);
		}
		char cs[2];
		cs[0] = c;
		cs[1] = '\0';
		RETURN_STRING(cs, 1);
	}
	else if (iequals(readAs, "byte"))
	{
		BYTE b = 0x0;
		if (!mem.Read<BYTE>(addr, b))
		{
			RETURN_STRING("Error: Read operation failed.", 1);
		}
		char cs[6];
		if (b > 0xF)
			sprintf_s(cs, 6, "0x%X", b);
		else
			sprintf_s(cs, 6, "0x0%X", b);
		RETURN_STRING(cs, 1);
	}
	else if (iequals(readAs, "string"))
	{
		if (bytes_num <= 0)
		{
			RETURN_STRING("Error: Cannot allocate zero sized buffer for string.", 1);
		}

		char* strbuf = new char[bytes_num];
		strbuf[0] = '\0';
		mem.ReadDataAsStringA(addr, strbuf, bytes_num);
		String sstr = strbuf;
		delete[] strbuf;
		RETURN_STRING(sstr.c_str(), 1);
	}
	else if (iequals(readAs, "int") || iequals(readAs, "long"))
	{
		int l = 0;
		if (mem.Read<int>(addr, l))
		{
			RETURN_LONG(l);
		}
		else
		{
			RETURN_STRING("Error: Read operation failed.", 1);
		}
	}
	else
	{
		RETURN_STRING("Error: Unknown type of value. Available types: bytes, byte, dword, pointer, int, long, float, double, bool, char, string", 1);
	}


}

PHP_FUNCTION(PowerMem_WriteProcessMemoryLong)
{
	long ProcessID;
	char *moduleName, *offset;
	int moduleName_len, offset_len;
	long longval;
	ProcMem mem;

#ifdef _DEBUG
	MessageBoxA(NULL, "Attach debugger to php.exe and click OK...", "Debug", MB_OK);
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s|s|l", &ProcessID, &moduleName, &moduleName_len, &offset, &offset_len, &longval) == FAILURE)
		return;

	if (ProcessID <= 0)
	{
		RETURN_STRING("Error: Process ID cannot be zero or lower than zero.", 1);
	}

	if (moduleName_len == 0)
	{
		RETURN_STRING("Error: Module name is empty.", 1);
	}

	if (!mem.Process(ProcessID))
	{
		RETURN_STRING("Error: Process not found.", 1);
	}

	DWORD base, dwOffset, addr;
	char* tmp;

	if (moduleName_len > 2 && moduleName[0] == '0' && (moduleName[1] == 'x' || moduleName[1] == 'X'))
		base = strtoul(moduleName, &tmp, 16);
	else
	{
		if (strcmp(moduleName, "BASE") == 0)
			base = mem.GetBase();
		else if (strcmp(moduleName, "NULL") == 0)
			base = 0;
		else
			base = mem.Module(moduleName);
	}

	if (offset_len == 0)
		dwOffset = 0;
	else if (offset_len > 2 && offset[0] == '0' && (offset[1] == 'x' || offset[1] == 'X'))
		dwOffset = strtoul(offset, &tmp, 16);
	else
		dwOffset = strtoul(offset, &tmp, 10);

	addr = base + dwOffset;
	mem.Write<long>(addr, longval);
}

PHP_FUNCTION(PowerMem_WriteProcessMemoryDword)
{
	long ProcessID;
	char *moduleName, *offset;
	int moduleName_len, offset_len;
	char* dwval; int dwlen;
	ProcMem mem;

#ifdef _DEBUG
	MessageBoxA(NULL, "Attach debugger to php.exe and click OK...", "Debug", MB_OK);
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s|s|s", &ProcessID, &moduleName, &moduleName_len, &offset, &offset_len, &dwval, &dwlen) == FAILURE)
		return;

	if (ProcessID <= 0)
	{
		RETURN_STRING("Error: Process ID cannot be zero or lower than zero.", 1);
	}

	if (moduleName_len == 0)
	{
		RETURN_STRING("Error: Module name is empty.", 1);
	}

	if (!mem.Process(ProcessID))
	{
		RETURN_STRING("Error: Process not found.", 1);
	}

	DWORD base, dwOffset, addr;
	char* tmp;

	if (moduleName_len > 2 && moduleName[0] == '0' && (moduleName[1] == 'x' || moduleName[1] == 'X'))
		base = strtoul(moduleName, &tmp, 16);
	else
	{
		if (strcmp(moduleName, "BASE") == 0)
			base = mem.GetBase();
		else if (strcmp(moduleName, "NULL") == 0)
			base = 0;
		else
			base = mem.Module(moduleName);
	}

	if (offset_len == 0)
		dwOffset = 0;
	else if (offset_len > 2 && offset[0] == '0' && (offset[1] == 'x' || offset[1] == 'X'))
		dwOffset = strtoul(offset, &tmp, 16);
	else
		dwOffset = strtoul(offset, &tmp, 10);

	addr = base + dwOffset;
	DWORD dwVal;
	if (dwlen == 0)
		dwVal = 0;
	else if (dwlen > 2 && dwval[0] == '0' && (dwval[1] == 'x' || dwval[1] == 'X'))
		dwVal = strtoul(dwval, &tmp, 16);
	else
		dwVal = strtoul(dwval, &tmp, 10);
	mem.Write<DWORD>(addr, dwVal);
}

PHP_FUNCTION(PowerMem_WriteProcessMemoryFloat)
{
	long ProcessID;
	char *moduleName, *offset;
	int moduleName_len, offset_len;
	double dval;
	float fval;
	ProcMem mem;

#ifdef _DEBUG
	MessageBoxA(NULL, "Attach debugger to php.exe and click OK...", "Debug", MB_OK);
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s|s|d", &ProcessID, &moduleName, &moduleName_len, &offset, &offset_len, &dval) == FAILURE)
		return;

	fval = float(dval);

	if (ProcessID <= 0)
	{
		RETURN_STRING("Error: Process ID cannot be zero or lower than zero.", 1);
	}

	if (moduleName_len == 0)
	{
		RETURN_STRING("Error: Module name is empty.", 1);
	}

	if (!mem.Process(ProcessID))
	{
		RETURN_STRING("Error: Process not found.", 1);
	}

	DWORD base, dwOffset, addr;
	char* tmp;

	if (moduleName_len > 2 && moduleName[0] == '0' && (moduleName[1] == 'x' || moduleName[1] == 'X'))
		base = strtoul(moduleName, &tmp, 16);
	else
	{
		if (strcmp(moduleName, "BASE") == 0)
			base = mem.GetBase();
		else if (strcmp(moduleName, "NULL") == 0)
			base = 0;
		else
			base = mem.Module(moduleName);
	}

	if (offset_len == 0)
		dwOffset = 0;
	else if (offset_len > 2 && offset[0] == '0' && (offset[1] == 'x' || offset[1] == 'X'))
		dwOffset = strtoul(offset, &tmp, 16);
	else
		dwOffset = strtoul(offset, &tmp, 10);

	addr = base + dwOffset;
	mem.Write<float>(addr, fval);
}

PHP_FUNCTION(PowerMem_WriteProcessMemoryDouble)
{
	long ProcessID;
	char *moduleName, *offset;
	int moduleName_len, offset_len;
	double dval;
	ProcMem mem;

#ifdef _DEBUG
	MessageBoxA(NULL, "Attach debugger to php.exe and click OK...", "Debug", MB_OK);
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s|s|d", &ProcessID, &moduleName, &moduleName_len, &offset, &offset_len, &dval) == FAILURE)
		return;

	if (ProcessID <= 0)
	{
		RETURN_STRING("Error: Process ID cannot be zero or lower than zero.", 1);
	}

	if (moduleName_len == 0)
	{
		RETURN_STRING("Error: Module name is empty.", 1);
	}

	if (!mem.Process(ProcessID))
	{
		RETURN_STRING("Error: Process not found.", 1);
	}

	DWORD base, dwOffset, addr;
	char* tmp;

	if (moduleName_len > 2 && moduleName[0] == '0' && (moduleName[1] == 'x' || moduleName[1] == 'X'))
		base = strtoul(moduleName, &tmp, 16);
	else
	{
		if (strcmp(moduleName, "BASE") == 0)
			base = mem.GetBase();
		else if (strcmp(moduleName, "NULL") == 0)
			base = 0;
		else
			base = mem.Module(moduleName);
	}

	if (offset_len == 0)
		dwOffset = 0;
	else if (offset_len > 2 && offset[0] == '0' && (offset[1] == 'x' || offset[1] == 'X'))
		dwOffset = strtoul(offset, &tmp, 16);
	else
		dwOffset = strtoul(offset, &tmp, 10);

	addr = base + dwOffset;
	mem.Write<double>(addr, dval);
}

PHP_FUNCTION(PowerMem_WriteProcessMemoryBool)
{
	long ProcessID;
	char *moduleName, *offset;
	int moduleName_len, offset_len;
	bool bval;
	ProcMem mem;

#ifdef _DEBUG
	MessageBoxA(NULL, "Attach debugger to php.exe and click OK...", "Debug", MB_OK);
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s|s|d", &ProcessID, &moduleName, &moduleName_len, &offset, &offset_len, &bval) == FAILURE)
		return;

	if (ProcessID <= 0)
	{
		RETURN_STRING("Error: Process ID cannot be zero or lower than zero.", 1);
	}

	if (moduleName_len == 0)
	{
		RETURN_STRING("Error: Module name is empty.", 1);
	}

	if (!mem.Process(ProcessID))
	{
		RETURN_STRING("Error: Process not found.", 1);
	}

	DWORD base, dwOffset, addr;
	char* tmp;

	if (moduleName_len > 2 && moduleName[0] == '0' && (moduleName[1] == 'x' || moduleName[1] == 'X'))
		base = strtoul(moduleName, &tmp, 16);
	else
	{
		if (strcmp(moduleName, "BASE") == 0)
			base = mem.GetBase();
		else if (strcmp(moduleName, "NULL") == 0)
			base = 0;
		else
			base = mem.Module(moduleName);
	}

	if (offset_len == 0)
		dwOffset = 0;
	else if (offset_len > 2 && offset[0] == '0' && (offset[1] == 'x' || offset[1] == 'X'))
		dwOffset = strtoul(offset, &tmp, 16);
	else
		dwOffset = strtoul(offset, &tmp, 10);

	addr = base + dwOffset;
	mem.Write<bool>(addr, bval);
}

PHP_FUNCTION(PowerMem_WriteProcessMemoryByte)
{
	long ProcessID;
	char *moduleName, *offset;
	int moduleName_len, offset_len;
	char* dwval; int dwlen;
	ProcMem mem;

#ifdef _DEBUG
	MessageBoxA(NULL, "Attach debugger to php.exe and click OK...", "Debug", MB_OK);
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s|s|s", &ProcessID, &moduleName, &moduleName_len, &offset, &offset_len, &dwval, &dwlen) == FAILURE)
		return;

	if (ProcessID <= 0)
	{
		RETURN_STRING("Error: Process ID cannot be zero or lower than zero.", 1);
	}

	if (moduleName_len == 0)
	{
		RETURN_STRING("Error: Module name is empty.", 1);
	}

	if (!mem.Process(ProcessID))
	{
		RETURN_STRING("Error: Process not found.", 1);
	}

	DWORD base, dwOffset, addr;
	char* tmp;

	if (moduleName_len > 2 && moduleName[0] == '0' && (moduleName[1] == 'x' || moduleName[1] == 'X'))
		base = strtoul(moduleName, &tmp, 16);
	else
	{
		if (strcmp(moduleName, "BASE") == 0)
			base = mem.GetBase();
		else if (strcmp(moduleName, "NULL") == 0)
			base = 0;
		else
			base = mem.Module(moduleName);
	}

	if (offset_len == 0)
		dwOffset = 0;
	else if (offset_len > 2 && offset[0] == '0' && (offset[1] == 'x' || offset[1] == 'X'))
		dwOffset = strtoul(offset, &tmp, 16);
	else
		dwOffset = strtoul(offset, &tmp, 10);

	addr = base + dwOffset;
	BYTE byval;
	if (dwlen == 0)
		byval = 0;
	else if (dwlen > 2 && dwval[0] == '0' && (dwval[1] == 'x' || dwval[1] == 'X'))
		byval = BYTE(strtoul(dwval, &tmp, 16));
	else
		byval = BYTE(strtoul(dwval, &tmp, 10));
	mem.Write<BYTE>(addr, byval);
}

PHP_FUNCTION(PowerMem_WriteProcessMemoryChar)
{
	long ProcessID;
	char *moduleName, *offset;
	int moduleName_len, offset_len;
	char* cval; int cvallen;
	ProcMem mem;

#ifdef _DEBUG
	MessageBoxA(NULL, "Attach debugger to php.exe and click OK...", "Debug", MB_OK);
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s|s|s", &ProcessID, &moduleName, &moduleName_len, &offset, &offset_len, &cval, &cvallen) == FAILURE)
		return;

	if (ProcessID <= 0)
	{
		RETURN_STRING("Error: Process ID cannot be zero or lower than zero.", 1);
	}

	if (cvallen == 0)
	{
		RETURN_STRING("Error: No character.", 1);
	}

	if (moduleName_len == 0)
	{
		RETURN_STRING("Error: Module name is empty.", 1);
	}

	if (!mem.Process(ProcessID))
	{
		RETURN_STRING("Error: Process not found.", 1);
	}

	DWORD base, dwOffset, addr;
	char* tmp;

	if (moduleName_len > 2 && moduleName[0] == '0' && (moduleName[1] == 'x' || moduleName[1] == 'X'))
		base = strtoul(moduleName, &tmp, 16);
	else
	{
		if (strcmp(moduleName, "BASE") == 0)
			base = mem.GetBase();
		else if (strcmp(moduleName, "NULL") == 0)
			base = 0;
		else
			base = mem.Module(moduleName);
	}

	if (offset_len == 0)
		dwOffset = 0;
	else if (offset_len > 2 && offset[0] == '0' && (offset[1] == 'x' || offset[1] == 'X'))
		dwOffset = strtoul(offset, &tmp, 16);
	else
		dwOffset = strtoul(offset, &tmp, 10);

	addr = base + dwOffset;
	mem.Write<char>(addr, cval[0]);
}

PHP_FUNCTION(PowerMem_WriteProcessMemoryString)
{
	long ProcessID;
	char *moduleName, *offset;
	int moduleName_len, offset_len;
	char* strval; int strvallen;
	ProcMem mem;

#ifdef _DEBUG
	MessageBoxA(NULL, "Attach debugger to php.exe and click OK...", "Debug", MB_OK);
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s|s|s", &ProcessID, &moduleName, &moduleName_len, &offset, &offset_len, &strval, &strvallen) == FAILURE)
		return;

	if (ProcessID <= 0)
	{
		RETURN_STRING("Error: Process ID cannot be zero or lower than zero.", 1);
	}

	if (moduleName_len == 0)
	{
		RETURN_STRING("Error: Module name is empty.", 1);
	}

	if (!mem.Process(ProcessID))
	{
		RETURN_STRING("Error: Process not found.", 1);
	}

	DWORD base, dwOffset, addr;
	char* tmp;

	if (moduleName_len > 2 && moduleName[0] == '0' && (moduleName[1] == 'x' || moduleName[1] == 'X'))
		base = strtoul(moduleName, &tmp, 16);
	else
	{
		if (strcmp(moduleName, "BASE") == 0)
			base = mem.GetBase();
		else if (strcmp(moduleName, "NULL") == 0)
			base = 0;
		else
			base = mem.Module(moduleName);
	}

	if (offset_len == 0)
		dwOffset = 0;
	else if (offset_len > 2 && offset[0] == '0' && (offset[1] == 'x' || offset[1] == 'X'))
		dwOffset = strtoul(offset, &tmp, 16);
	else
		dwOffset = strtoul(offset, &tmp, 10);

	addr = base + dwOffset;
	mem.WriteStringA(addr, strval);
}

PHP_FUNCTION(PowerMem_WriteProcessMemoryBytes)
{
	long ProcessID;
	char *moduleName, *offset;
	int moduleName_len, offset_len;
	zval *arr, *data;
	HashTable *arr_hash;
	int arr_size;
	ProcMem mem;

#ifdef _DEBUG
	MessageBoxA(NULL, "Attach debugger to php.exe and click OK...", "Debug", MB_OK);
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s|s|a", &ProcessID, &moduleName, &moduleName_len, &offset, &offset_len, &arr) == FAILURE)
		return;

	arr_hash = Z_ARRVAL_P(arr);
	arr_size = zend_hash_num_elements(arr_hash);

	if (arr_size == 0)
	{
		RETURN_STRING("Error: Empty data array.", 1);
	}

	if (ProcessID <= 0)
	{
		RETURN_STRING("Error: Process ID cannot be zero or lower than zero.", 1);
	}

	if (moduleName_len == 0)
	{
		RETURN_STRING("Error: Module name is empty.", 1);
	}

	if (!mem.Process(ProcessID))
	{
		RETURN_STRING("Error: Process not found.", 1);
	}

	DWORD base, dwOffset, addr;
	char* tmp;

	if (moduleName_len > 2 && moduleName[0] == '0' && (moduleName[1] == 'x' || moduleName[1] == 'X'))
		base = strtoul(moduleName, &tmp, 16);
	else
	{
		if (strcmp(moduleName, "BASE") == 0)
			base = mem.GetBase();
		else if (strcmp(moduleName, "NULL") == 0)
			base = 0;
		else
			base = mem.Module(moduleName);
	}

	if (offset_len == 0)
		dwOffset = 0;
	else if (offset_len > 2 && offset[0] == '0' && (offset[1] == 'x' || offset[1] == 'X'))
		dwOffset = strtoul(offset, &tmp, 16);
	else
		dwOffset = strtoul(offset, &tmp, 10);

	addr = base + dwOffset;

	BYTE* raw = new BYTE[arr_size];
	HashPosition pointer;
	size_t i = 0;
	long lval;
	char* sval; int slen;

	for (zend_hash_internal_pointer_reset_ex(arr_hash, &pointer); data = zend_hash_get_current_data_ex(arr_hash, &pointer); zend_hash_move_forward_ex(arr_hash, &pointer)) 
	{

		if (Z_TYPE_P(data) == IS_LONG) 
			lval = Z_LVAL_P(data);
		else if (Z_TYPE_P(data) == IS_STRING)
		{
			sval = Z_STRVAL_P(data);
			slen = Z_STRLEN_P(data);

			if (slen > 2 && sval[0] == '0' && (sval[1] == 'x' || sval[1] == 'X'))
				lval = strtol(offset, &tmp, 16);
			else
				lval = strtol(offset, &tmp, 10);
		}
		else
		{
			delete[] raw;
			RETURN_STRING("Error: Unknown array format. Bytes should be 'long' or 'string' elements.", 1);
		}

		raw[i] = BYTE(lval);
		i++;
	}

	mem.WriteBinaryData(addr, raw, arr_size);
	delete[] raw;
}

PHP_FUNCTION(PowerMem_ShellExecute)	 //(string operation, string file, string parameters, string directory, long nShowCmd)
{
	char *operation, *file, *parameters, *directory;
	int ol, fl, pl, dl;
	long nShowCmd;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s|s|s|l", &operation, &ol, &file, &fl, &parameters, &pl, &directory, &dl, &nShowCmd) == FAILURE)
		return;

	ShellExecuteA(NULL, operation, file, parameters, directory, nShowCmd);
	RETURN_NULL();
} 

PHP_FUNCTION(PowerMem_PatternScan)
{
	long ProcessID;
	char* module, *pattern, *method, *pat_offset, *addr_offset;
	int mo_l, pa_l, me_l, pof_l, aof_l;
	DWORD dwPatOff, dwAddrOff;
	ProcMem mem;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s|s|s|s|s", &ProcessID, &module, &mo_l, &pattern, &pa_l, &method, &me_l, &pat_offset, &pof_l, &addr_offset, &aof_l) == FAILURE)
		return;

#ifdef _DEBUG
	MessageBoxA(NULL, "Attach debugger to php.exe and click OK...", "Debug", MB_OK);
#endif
	
	if (ProcessID <= 0)
	{
		RETURN_STRING("Error: Process ID cannot be zero or lower than zero.", 1);
	}

	if (mo_l == 0)
	{
		RETURN_STRING("Error: Module is empty.", 1);
	}

	if (pa_l == 0)
	{
		RETURN_STRING("Error: Pattern is empty.", 1);
	}

	if (me_l == 0)
	{
		RETURN_STRING("Error: Method is empty.", 1);
	}

	if (!iequals(method, "normal") && !iequals(method, "read") && !iequals(method, "substract") && !iequals(method, "both"))
	{
		RETURN_STRING("Error: Unknown method. Please, use one of available methods: normal, read, substract, both", 1);
	}

	if (!mem.Process(ProcessID))
	{
		RETURN_STRING("Error: Process not found.", 1);
	}

	char* tmp;
	if (pof_l == 0)
		dwPatOff = 0;
	else if (pof_l > 2 && pat_offset[0] == '0' && (pat_offset[1] == 'x' || pat_offset[1] == 'X'))
		dwPatOff = strtoul(pat_offset, &tmp, 16);
	else
		dwPatOff = strtoul(pat_offset, &tmp, 10);

	if (aof_l == 0)
		dwAddrOff = 0;
	else if (aof_l > 2 && addr_offset[0] == '0' && (addr_offset[1] == 'x' || addr_offset[1] == 'X'))
		dwAddrOff = strtoul(addr_offset, &tmp, 16);
	else
		dwAddrOff = strtoul(addr_offset, &tmp, 10);

	DWORD result = mem.PatternScan(module, pattern, method, dwPatOff, dwAddrOff);
	char pszResultX[32];
	sprintf_s(pszResultX, 32, "0x%X", result);
	RETURN_STRING(pszResultX, 1);
}

PHP_FUNCTION(PowerMem_SRC_GetNetVarOffset) //(long processID, string tableName, string varName, string offset)
{
	long ProcessID;
	char* tableName, *varName, *offset;
	int tnl, vnl, offl;
	DWORD dwOff;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s|s|s", &ProcessID, &tableName, &tnl, &varName, &vnl, &offset, &offl) == FAILURE)
		return;

#ifdef _DEBUG
	MessageBoxA(NULL, "Attach debugger to php.exe and click OK...", "Debug", MB_OK);
#endif

	if (ProcessID <= 0)
	{
		RETURN_STRING("Error: Process ID cannot be zero or lower than zero.", 1);
	}

	if (tnl == 0)
	{
		RETURN_STRING("Error: Module is empty.", 1);
	}

	if (vnl == 0)
	{
		RETURN_STRING("Error: Pattern is empty.", 1);
	}

	char* tmp;
	if (offl == 0)
		dwOff = 0;
	else if (offl > 2 && offset[0] == '0' && (offset[1] == 'x' || offset[1] == 'X'))
		dwOff = strtoul(offset, &tmp, 16);
	else
		dwOff = strtoul(offset, &tmp, 10);

	DWORD netvar = 0;

	if (!GetNetvar(ProcessID, tableName, varName, dwOff, netvar))
	{
		RETURN_STRING("Error: Failed to read netvar.", 1);
	}

	char pszResultX[32];
	sprintf_s(pszResultX, 32, "0x%X", netvar);
	RETURN_STRING(pszResultX, 1);
}