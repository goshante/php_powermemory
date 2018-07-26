#ifndef _NETVARMANAGER_H_
#define _NETVARMANAGER_H_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif /* WIN32_LEAN_AND_MEAN */

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif /* _CRT_SECURE_NO_WARNINGS */

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <unordered_map>
#include "ProcMem.h"

//#pragma warning( disable : 4227 )
//#pragma warning( disable : 4172 )


class CMemory
{
public:
	typedef std::vector<BYTE> vecByte_t;

	CMemory(const uintptr_t& base, const size_t& size, DWORD processID);
	~CMemory(void);


	const uintptr_t&                        Get(void) const;
	template <typename _Ty>
	_Ty Get(const uintptr_t& off = 0x0)
	{
		if (off < _bytes.size()) 
			return *reinterpret_cast< _Ty* >(&_bytes.at(off));
		return _Ty();
	}

protected:

	uintptr_t                               _base;
	vecByte_t                               _bytes;
	ProcMem									_procMem;
};

class PropType_t
{
public:
	enum
	{
		DPT_Int = 0,
		DPT_Float,
		DPT_Vector,
		DPT_VectorXY,
		DPT_String,
		DPT_Array,
		DPT_DataTable,
		DPT_NUMSendPropTypes
	};

	static std::string toString(int v, int e, int c)
	{
		switch (v) {
		case DPT_Int:
			return "int";
		case DPT_Float:
			return "float";
		case DPT_Vector:
			return "Vec3";
		case DPT_VectorXY:
			return "Vec2";
		case DPT_String:
			return "char[ " + std::to_string(c) + " ]";
		case DPT_Array:
			return "[ " + std::to_string(e) + " ]";
		case DPT_DataTable:
			return "void*";
		default:
			return "";
		}
	}
};

class RecvTable : public CMemory
{
public:

	explicit RecvTable(const uintptr_t& base, DWORD procID);
	~RecvTable(void) = default;

	std::string                             GetTableName(void);
	std::string                             GetClassNameA(void);
	uintptr_t                               GetPropById(int id);
	int                                     GetPropCount(void);
};

class RecvProp : public CMemory
{
public:

	RecvProp(const uintptr_t& base, int level, int offset, DWORD procID);
	~RecvProp(void) = default;

	uintptr_t                               GetTable(void);
	std::string                             GetPropName(void);
	int                                     GetPropOffset(void);
	int                                     GetPropType(void);
	int                                     GetPropElements(void);
	int                                     GetPropStringBufferCount(void);
	const int&                              GetLevel(void) const;

protected:

	int                                     _level;                       // level
	int                                     _offset;                       // level
};

class ClientClass : public CMemory
{
public:

	explicit ClientClass(const uintptr_t& base, DWORD procID);
	~ClientClass(void) = default;

	int                                     GetClassId(void);
	std::string                             GetClassNameA(void);
	uintptr_t                               GetNextClass(void);
	uintptr_t                               GetTable(void);
};

typedef std::unordered_map< std::string, std::vector<std::pair<std::string, RecvProp*>> >   mapTable;

class CNetVarManager
{

protected:
	mapTable                                _tables;                
	DWORD									_procID;

private:
	void                                    ScanTable(DWORD procID, RecvTable& table, int level, int offset, const char* name);

public:
	CNetVarManager(DWORD procID);
	~CNetVarManager();

	bool                                    Load();
	int                                     GetNetVar(const std::string& tablename, const std::string& varname);
	
};


#endif 
