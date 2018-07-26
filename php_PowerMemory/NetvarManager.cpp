#include "defs.h"
#include "NetVarManager.h"
#include <iomanip>
#include <sstream>
#include "utils.h"


CMemory::CMemory(const uintptr_t& base, const size_t& size, DWORD processID) :
	_base(base),
	_procMem(processID)
{
	_bytes = vecByte_t(size);
	if (!_base || !_procMem.ReadBinaryData(_base, &_bytes.at(0), size, false)) 
		_bytes = vecByte_t(0);
}

CMemory::~CMemory(void)
{
	if (!_bytes.empty()) 
		_bytes.clear();
}

const uintptr_t& CMemory::Get(void) const
{
	return _base;
}




RecvTable::RecvTable(const uintptr_t& base, DWORD procID) :
	CMemory(base, 0x10, procID)
{
}

uintptr_t RecvTable::GetPropById(int id)
{
	return Get<uintptr_t>() + id * 0x3C;
}

std::string RecvTable::GetTableName(void)
{
	auto toReturn = std::string("", 32); 
	_procMem.ReadDataAsStringA(Get<DWORD>(0xC), &toReturn.at(0), 32);
	return toReturn;
}

std::string RecvTable::GetClassNameA(void)
{
	auto toReturn = GetTableName();
	toReturn.replace(toReturn.begin(), toReturn.begin() + 3, "C");
	return toReturn;
}

int RecvTable::GetPropCount(void)
{
	return Get<int>(0x4);
}

RecvProp::RecvProp(const uintptr_t& base, int level, int offset, DWORD procID) :
	CMemory(base, 0x3C, procID),
	_level(level),
	_offset(offset)
{
}

uintptr_t RecvProp::GetTable(void)
{
	return Get<uintptr_t>(0x28);
}

std::string RecvProp::GetPropName(void)
{
	auto toReturn = std::string("", 64);
	_procMem.ReadDataAsStringA(Get<DWORD>(), &toReturn.at(0), 64);
	return toReturn;
}

int RecvProp::GetPropOffset(void)
{
	return _offset + Get<int>(0x2C);
}

int RecvProp::GetPropType(void)
{
	return Get<int>(0x4);
}

int RecvProp::GetPropElements(void)
{
	return Get<int>(0x34);
}

int RecvProp::GetPropStringBufferCount()
{
	return Get<int>(0xC);
}

const int& RecvProp::GetLevel(void) const
{
	return _level;
}

ClientClass::ClientClass(const uintptr_t& base, DWORD procID) :
	CMemory(base, 0x28, procID)
{
}

int ClientClass::GetClassId(void)
{
	return Get<int>(0x14);
}

std::string ClientClass::GetClassNameA(void)
{
	auto toReturn = std::string("", 64);
	_procMem.ReadDataAsStringA(Get<DWORD>(0x8), &toReturn.at(0), 64);
	return toReturn;
}

uintptr_t ClientClass::GetNextClass(void)
{
	return Get<uintptr_t>(0x10);
}

uintptr_t ClientClass::GetTable(void)
{
	return Get<uintptr_t>(0xC);
}

CNetVarManager::CNetVarManager(DWORD procID)
{
	_procID = procID;
}

CNetVarManager::~CNetVarManager()
{
	for (auto& table : _tables)
	{
		for (auto& prop : table.second)
			delete prop.second;
		table.second.clear();
	}
	_tables.clear();
}

bool CNetVarManager::Load()
{
	ProcMem procMemManager(_procID);
	auto firstclass = procMemManager.PatternScan("client.dll", "44 54 5F 54 45 57 6F 72 6C 64 44 65 63 61 6C", "NORMAL", 0, 0);

	std::stringstream ss;
	for (auto i = 0; i < 4; ++i) 
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << ((firstclass >> 8 * i) & 0xFF) << " ";
	}

	firstclass = procMemManager.PatternScan("client.dll", ss.str().c_str(), "READ", 0x2B, 0);
	procMemManager.Free();

	if (!firstclass)
		return false;

	for (auto Class = ClientClass(firstclass, _procID); Class.Get(); Class = ClientClass(Class.GetNextClass(), _procID)) 
	{

		auto table = RecvTable(Class.GetTable(), _procID);
		if (!table.Get())
			continue;

		ScanTable(_procID, table, 0, 0, table.GetTableName().c_str());
	}
	return true;
}

int CNetVarManager::GetNetVar(const std::string& tablename, const std::string& varname)
{
	auto table = _tables.find(tablename);
	if (table != _tables.end()) 
	{
		for (auto& prop : table->second) 
		{
			if (prop.first == varname)
				return prop.second->GetPropOffset();
		}
	}
	return 0;
}

void CNetVarManager::ScanTable(DWORD procID, RecvTable& table, int level, int offset, const char* name)
{
	auto count = table.GetPropCount();
	for (auto i = 0; i < count; ++i) 
	{

		auto prop = new RecvProp(table.GetPropById(i), level, offset, procID);
		auto propName = prop->GetPropName();

		if (isdigit(propName[0]))
			continue;

		auto isBaseClass = !strcmp(propName.c_str(), "baseclass");
		if (!isBaseClass) 
		{
			_tables[name].push_back({propName.c_str(), prop});
		}

		auto child = prop->GetTable();
		if (!child)
			continue;

		auto recvTable = RecvTable(child, procID);

		if (isBaseClass) 
		{
			_tables[name].push_back({recvTable.GetTableName(), prop});
			--level;
		}

		ScanTable(procID, recvTable, ++level, prop->GetPropOffset(), name);
	}
}