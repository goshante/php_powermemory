#include "defs.h"
#include "NetVarManager.h"
#include <iomanip>
#include <sstream>
#include "utils.h"

namespace Dumper
{

	namespace Remote
	{
		CMemory::CMemory(const uintptr_t& base, const size_t& size) :
			_base(base)
		{
			_bytes = vecByte(size);
			if (!_base || !pProcess->ReadMemory(_base, static_cast< void* >(&_bytes.at(0)), size)) {
				_bytes = vecByte(0);
			}
		}

		CMemory::~CMemory(void)
		{
			if (!_bytes.empty()) {
				_bytes.clear();
			}
		}

		const uintptr_t& CMemory::Get(void) const
		{
			return _base;
		}

		CModule::CModule(const std::string& name, const std::string& path, const uintptr_t& imgsize, const intptr_t& imgbase) :
			_name(name),
			_path(path),
			_imgsize(imgsize),
			_imgbase(imgbase)
		{
			_bytes = vecByte(imgsize);
			pProcess->ReadMemory(_imgbase, &_bytes[0], _imgsize);
		}

		CModule::~CModule(void)
		{
			if (!_bytes.empty()) {
				_bytes.clear();
			}
		}

		uintptr_t CModule::operator+(uintptr_t offset) const
		{
			return _imgbase + offset;
		}

		uintptr_t CModule::operator-(uintptr_t offset) const
		{
			return _imgbase - offset;
		}

		const std::string& CModule::GetName() const
		{
			return _name;
		}

		const std::string& CModule::GetPath() const
		{
			return _path;
		}

		const uintptr_t& CModule::GetImgSize() const
		{
			return _imgsize;
		}

		const uintptr_t& CModule::GetImgBase() const
		{
			return _imgbase;
		}

		const vecByte& CModule::GetDumpedBytes() const
		{
			return _bytes;
		}

		bool CProcess::Attach(long processID, const std::string& winname /* = std::string( ) */, const std::string& winclname /* = std::string( ) */, DWORD accessrights /* = PROCESS_ALL_ACCESS */, DWORD maxwtime /* = 0 */)
		{
			Detach();
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, processID);

			if (!hProcess)
				return false;

			HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);
			MODULEENTRY32 mEntry;
			mEntry.dwSize = sizeof(mEntry);
			Module32First(hModule, &mEntry);
			CloseHandle(hModule);

			_procname = mEntry.szModule;
			_winname = winname;
			_winclname = winclname;

			_accessrights = accessrights;
			_haswindow = bool(!_winname.empty() || !_winclname.empty());

			_hproc = hProcess;
			_procid = processID;

			auto curtime = GetTickCount();
			do 
			{
				if (GetProcessModules())
					return true;
			} while ((maxwtime != 0 ? (GetTickCount() - curtime) <= maxwtime : true));

			return false;
		}

		void CProcess::Detach(void)
		{
			if (!_modules.empty()) {
				for (auto& m : _modules) {
					delete m.second;
				}
				_modules.clear();
			}

			_procname.clear();
			_winname.clear();
			_winclname.clear();

			_procid = 0;
			_hproc = nullptr;
		}

		bool CProcess::ReadMemory(const uintptr_t& address, void* pBuffer, size_t size) const
		{
			return bool(ReadProcessMemory(_hproc, LPCVOID(address), pBuffer, size, nullptr) == TRUE);
		}

		bool CProcess::WriteMemory(uintptr_t& address, const void* pBuffer, size_t size) const
		{
			return bool(WriteProcessMemory(_hproc, LPVOID(address), pBuffer, size, nullptr) == TRUE);
		}

		bool CProcess::CompareBytes(const unsigned char* bytes, const char* pattern)
		{
			for (; *pattern; *pattern != ' ' ? ++bytes : bytes, ++pattern) {
				if (*pattern == ' ' || *pattern == '?')
					continue;
				if (*bytes != getByte(pattern))
					return false;
				++pattern;
			}
			return true;
		}

		uintptr_t CProcess::FindPattern(const std::string& module, const char* pattern, short type, uintptr_t patternOffset, uintptr_t addressOffset)
		{
			auto mod = GetModuleByName(module);
			if (!mod)
				return 0;

			auto pb = const_cast< unsigned char* >(&mod->GetDumpedBytes().at(0));
			auto max = mod->GetImgSize() - 0x1000;

			for (auto off = 0UL; off < max; ++off) {
				if (CompareBytes(pb + off, pattern)) {

					auto add = mod->GetImgBase() + off + patternOffset;

					if (type & SignatureType_t::READ)
						ReadMemory(add, &add, sizeof(uintptr_t));

					if (type & SignatureType_t::SUBTRACT)
						add -= mod->GetImgBase();

					return add + addressOffset;
				}
			}
			return 0;
		}

		bool CProcess::GetProcessModules(void)
		{
			if (_hproc == nullptr) {
				return false;
			}

			auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, _procid);
			if (!hSnapshot) {
				return false;
			}

			MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
			if (Module32First(hSnapshot, &me32) == TRUE) {
				do {
					char path[MAX_PATH] = { 0 };
					GetModuleFileNameExA(_hproc, me32.hModule, path, MAX_PATH);

					_modules[me32.szModule] = new CModule(me32.szModule, path, uintptr_t(me32.modBaseSize), uintptr_t(me32.hModule));
				} while (Module32Next(hSnapshot, &me32) == TRUE);
			}

			CloseHandle(hSnapshot);

			if (_modules.find("client.dll") == _modules.end()) 
			{ 
				if (!_modules.empty()) {
					for (auto& m : _modules) {
						delete m.second;
					}
					_modules.clear();
				}
			}
			return bool(!_modules.empty());
		}

		const mapModule& CProcess::GetModules() const
		{
			return _modules;
		}

		CModule* CProcess::GetModuleByName(const std::string& name)
		{
			auto res = _modules.find(name);
			if (res != _modules.end()) {
				return res->second;
			}
			return nullptr;
		}

		CProcess* CProcess::Singleton(void)
		{
			static auto g_pProcess = new CProcess();
			return g_pProcess;
		}
	}


	namespace NetVarManager
	{
		RecvTable::RecvTable(const uintptr_t& base) :
			CMemory(base, 0x10)
		{
		}

		uintptr_t RecvTable::GetPropById(int id)
		{
			return Get<uintptr_t>() + id * 0x3C;
		}

		std::string RecvTable::GetTableName(void)
		{
			auto toReturn = std::string("", 32);
			pProcess->ReadMemory(Get<DWORD>(0xC), &toReturn.at(0), 32);
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

		RecvProp::RecvProp(const uintptr_t& base, int level, int offset) :
			CMemory(base, 0x3C),
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
			pProcess->ReadMemory(Get<DWORD>(), &toReturn.at(0), 64);
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

		ClientClass::ClientClass(const uintptr_t& base) :
			CMemory(base, 0x28)
		{
		}

		int ClientClass::GetClassId(void)
		{
			return Get<int>(0x14);
		}

		std::string ClientClass::GetClassNameA(void)
		{
			auto toReturn = std::string("", 64);
			pProcess->ReadMemory(Get<DWORD>(0x8), &toReturn.at(0), 64);
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

		bool CNetVarManager::Load(void)
		{
			auto firstclass = pProcess->FindPattern("client.dll", "44 54 5F 54 45 57 6F 72 6C 64 44 65 63 61 6C", 0, 0, 0);

			std::stringstream ss;
			for (auto i = 0; i < 4; ++i) {
				ss << std::hex << std::setw(2) << std::setfill('0') << ((firstclass >> 8 * i) & 0xFF) << " ";
			}

			firstclass = pProcess->FindPattern("client.dll", ss.str().c_str(), Remote::SignatureType_t::READ, 0x2B, 0);

			if (!firstclass)
				return false;

			for (auto Class = ClientClass(firstclass); Class.Get(); Class = ClientClass(Class.GetNextClass())) {

				auto table = RecvTable(Class.GetTable());
				if (!table.Get())
					continue;

				ScanTable(table, 0, 0, table.GetTableName().c_str());
			}
			return true;
		}

		void CNetVarManager::Release(void)
		{
			for (auto& table : _tables) {
				for (auto& prop : table.second) {
					delete prop.second;
				}
				table.second.clear();
			}
			_tables.clear();
		}

		int CNetVarManager::GetNetVar(const std::string& tablename, const std::string& varname)
		{
			auto table = _tables.find(tablename);
			if (table != _tables.end()) {
				for (auto& prop : table->second) {
					if (prop.first == varname)
						return prop.second->GetPropOffset();
				}
			}
			return 0;
		}

		void CNetVarManager::ScanTable(RecvTable& table, int level, int offset, const char* name)
		{
			auto count = table.GetPropCount();
			for (auto i = 0; i < count; ++i) {

				auto prop = new RecvProp(table.GetPropById(i), level, offset);
				auto propName = prop->GetPropName();

				if (isdigit(propName[0]))
					continue;

				auto isBaseClass = !strcmp(propName.c_str(), "baseclass");
				if (!isBaseClass) {
					_tables[name].push_back({
						propName.c_str(), prop
						});
				}

				auto child = prop->GetTable();
				if (!child)
					continue;

				auto recvTable = RecvTable(child);

				if (isBaseClass) {
					_tables[name].push_back({
						recvTable.GetTableName(), prop
						});
					--level;
				}

				ScanTable(recvTable, ++level, prop->GetPropOffset(), name);
			}
		}

		CNetVarManager* CNetVarManager::Singleton(void)
		{
			static auto g_pNetVarManager = new CNetVarManager();
			return g_pNetVarManager;
		}
	}
}