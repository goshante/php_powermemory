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



namespace Dumper
{
	namespace Remote
	{
		class CProcess;
		class CModule;

		class SignatureType_t
		{
		public:
			enum
			{
				NORMAL = 0x0, // normal
				READ = 0x1, // rpm at pattern
				SUBTRACT = 0x2, // subtract img base
			};
		};

		typedef std::vector<unsigned char>                      vecByte;
		typedef std::unordered_map<std::string, CModule*>       mapModule;

		class CMemory
		{
		public:

			CMemory(const uintptr_t& base, const size_t& size);
			~CMemory(void);

			template <typename _Ty> _Ty             Get(const uintptr_t& off = 0x0);
			const uintptr_t&                        Get(void) const;

		protected:

			uintptr_t                               _base;                  // base
			vecByte                                 _bytes;                 // bytes
		};

		template <typename _Ty>
		_Ty CMemory::Get(const uintptr_t& off)
		{
			if (off < _bytes.size()) {
				return *reinterpret_cast< _Ty* >(&_bytes.at(off));
			}
			return _Ty();
		}

		class CModule
		{
		public:

			CModule(const std::string& name, const std::string& path, const uintptr_t& imgsize, const intptr_t& imgbase);
			~CModule(void);

			uintptr_t operator+(uintptr_t offset) const;
			uintptr_t operator-(uintptr_t offset) const;

			const std::string&                      GetName(void) const;
			const std::string&                      GetPath(void) const;
			const uintptr_t&                        GetImgSize(void) const;
			const uintptr_t&                        GetImgBase(void) const;
			const vecByte&                          GetDumpedBytes(void) const;


		protected:

			std::string                             _name;                  // module name
			std::string                             _path;                  // module path

			uintptr_t                               _imgsize = 0;           // image size
			uintptr_t                               _imgbase = 0;           // image base

			vecByte                                 _bytes;                 // dumped byte of the module
		};

		class CProcess
		{
		public:

			bool                                    Attach(long processID,
				const std::string& winname = std::string(),
				const std::string& winclname = std::string(),
				DWORD accessrights = PROCESS_ALL_ACCESS,
				DWORD maxwtime = 0);
			void                                    Detach(void);

			bool                                    ReadMemory(const uintptr_t& address, void* pBuffer, size_t size) const;
			bool                                    WriteMemory(uintptr_t& address, const void* pBuffer, size_t size) const;

			static bool                             CompareBytes(const unsigned char* bytes, const char* pattern);
			uintptr_t                               FindPattern(const std::string& module, const char* pattern, short type, uintptr_t patternOffset, uintptr_t addressOffset);

		private:

			bool                                    GetProcessModules(void);

		public:

			const mapModule&                        GetModules(void) const;
			CModule*                                GetModuleByName(const std::string& name);

		protected:

			std::string                             _procname;              // process name
			std::string                             _winname;               // window name
			std::string                             _winclname;             // window class

			DWORD                                   _accessrights = 0;      // openprocess rights
			bool                                    _haswindow = false;     // has the process a window
			DWORD                                   _procid = 0;            // process id
			HANDLE                                  _hproc = nullptr;       // process handle

			mapModule                               _modules;               // unordered_map holds modules
		public:
			static CProcess* Singleton(void);
		};
	}
}

#ifndef pProcess
#define pProcess Dumper::Remote::CProcess::Singleton( )
#endif /* pProcess */


#pragma warning( disable : 4227 )
#pragma warning( disable : 4172 )

namespace Dumper
{
	namespace NetVarManager
	{
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

		class RecvTable : public Remote::CMemory
		{
		public:

			explicit RecvTable(const uintptr_t& base);
			~RecvTable(void) = default;

			std::string                             GetTableName(void);
			std::string                             GetClassNameA(void);
			uintptr_t                               GetPropById(int id);
			int                                     GetPropCount(void);
		};

		class RecvProp : public Remote::CMemory
		{
		public:

			RecvProp(const uintptr_t& base, int level, int offset);
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

		class ClientClass : public Remote::CMemory
		{
		public:

			explicit ClientClass(const uintptr_t& base);
			~ClientClass(void) = default;

			int                                     GetClassId(void);
			std::string                             GetClassNameA(void);
			uintptr_t                               GetNextClass(void);
			uintptr_t                               GetTable(void);
		};

		typedef std::unordered_map< std::string, std::vector<std::pair<std::string, RecvProp*>> >   mapTable;

		class CNetVarManager
		{
		public:

			bool                                    Load(void);
			void                                    Release(void);

			int                                     GetNetVar(const std::string& tablename, const std::string& varname);

		private:

			void                                    ScanTable(RecvTable& table, int level, int offset, const char* name);

		protected:

			mapTable                                _tables;                    // recvtables dumped

		public:
			static CNetVarManager* Singleton(void);
		};
	}
}

#ifndef pNetVarManager
#define pNetVarManager Dumper::NetVarManager::CNetVarManager::Singleton( )
#endif

#pragma warning( default : 4172 )
#pragma warning( default : 4227 )

#endif 
