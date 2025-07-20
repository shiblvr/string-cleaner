#include <util.hpp>
#include <print.hpp>
#include <TlHelp32.h>
#include <unordered_map>

pNtWriteVirtualMemory       NtWriteVirtualMemory       = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
pNtReadVirtualMemory        NtReadVirtualMemory        = (pNtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
pNtQueryVirtualMemory       NtQueryVirtualMemory       = (pNtQueryVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVirtualMemory");
pNtClose				    NtClose                    = (pNtClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose");
pNtOpenProcess              NtOpenProcess              = (pNtOpenProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");


namespace u {

	std::wstring GetProcessName(DWORD PID) {
		HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID);
		if (!hProc)
			return L"?";

		wchar_t buffer[MAX_PATH] = { 0 };
		DWORD size = MAX_PATH;

		if (!QueryFullProcessImageNameW(hProc, 0, buffer, &size)) {
			print::debugln("GetProcessName - QueryFullProcessImageNameW failed. Err: {}", GetLastError());
			CloseHandle(hProc);
			return L"?";
		}

		CloseHandle(hProc);
		std::wstring fullPath(buffer);

		size_t pos = fullPath.find_last_of(L'\\');

		if (pos == std::wstring::npos)
			return fullPath;

		return fullPath.substr(pos + 1);
	}

	bool is_system() {

		HANDLE hToken = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			print::debugln("is_system - OpenProcessToken failed.", GetLastError());
			return false;
		}
		DWORD size = 0;
		GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &size);

		std::vector<BYTE> buffer(size);
		PTOKEN_PRIVILEGES privileges = reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data());

		if (!GetTokenInformation(hToken, TokenPrivileges, privileges, size, &size)) {
			print::debugln("is_system - GetTokenInformation failed.", GetLastError());
			return false;
		}

		LUID luid;
		if (!LookupPrivilegeValueW(NULL, L"SeTcbPrivilege", &luid)) {
			print::debugln("is_system - LookupPrivilegeValueW failed.", GetLastError());
			return false;
		}

		for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
			if (privileges->Privileges[i].Luid.LowPart == luid.LowPart &&
				privileges->Privileges[i].Luid.HighPart == luid.HighPart) {

				return (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
			}
		}
		return false;
	}
	bool is_admin() {

		HANDLE hToken{};

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {

			print::debugln("is_admin - OpenProcessToken failed. Err: {}", GetLastError());
			return false;
		}

		TOKEN_ELEVATION elevation{};
		DWORD size = sizeof(elevation);

		if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {

			print::debugln("is_admin - GetTokenInformation failed. Err {}", GetLastError());
			return false;
		}

		if (elevation.TokenIsElevated) {
			return true;
		}

		return false;
	}

	 DWORD get_process_id(const wchar_t* processName) {

		DWORD PID{ 0 };
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (!hSnapshot) {
			print::errorln("Snapshot failed.");
			std::cin.get();
			return 0;
		}

		PROCESSENTRY32W pe32{};
		pe32.dwSize = sizeof(PROCESSENTRY32W);

		while (Process32NextW(hSnapshot, &pe32)) {
			if (wcscmp(pe32.szExeFile, processName) == 0) {
				PID = pe32.th32ProcessID;
				break;
			}
		}
		CloseHandle(hSnapshot);
		return PID; 
	}

	bool steal_sys_token() {
		DWORD pid = get_process_id(L"winlogon.exe");
		if (!pid) {
			return false;
		}

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProcess) {
			print::debugln("steal_sys_token OpenProcess failed. Err: {}", GetLastError());
			return false;
		}

		HANDLE hProcToken = nullptr;
		if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hProcToken)) {
			print::debugln("steal_sys_token OpenProcessToken. Err: {}", GetLastError());
			CloseHandle(hProcess);
			return false;
		}

		HANDLE hDupToken = nullptr;
		if (!DuplicateTokenEx(hProcToken, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &hDupToken)) {
			print::debugln("steal_sys_token DuplicateTokenEx. Err: {}", GetLastError());
			CloseHandle(hProcToken);
			CloseHandle(hProcess);
			return false;
		}

		wchar_t path[MAX_PATH];
		GetModuleFileNameW(NULL, path, MAX_PATH);

		STARTUPINFOW si = { sizeof(si) };
		PROCESS_INFORMATION pi = {};

		if (!CreateProcessWithTokenW(
			hDupToken,
			LOGON_WITH_PROFILE,
			path,
			NULL,
			CREATE_NEW_CONSOLE,
			NULL,
			NULL,
			&si,
			&pi)) {
			CloseHandle(hDupToken);
			CloseHandle(hProcToken);
			CloseHandle(hProcess);

			print::debugln("steal_sys_token CreateProcessWithTokenW failed.", GetLastError());

			return false;

			
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hDupToken);
		CloseHandle(hProcToken);
		CloseHandle(hProcess);

		return true;
	}
	bool enable_privilege(const wchar_t* privilege) {

		HANDLE hToken{};
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
			print::debugln("EnablePrivilege - OpenProcessToken failed. Err: {}", GetLastError()); 
			return false;
		}

		TOKEN_PRIVILEGES tp{};
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = { 0 };
		if (!LookupPrivilegeValueW(NULL, privilege, &tp.Privileges[0].Luid)) {
			print::debugln("EnablePrivilege - LookupPrivilegeValueW failed. Err {}", GetLastError()); 
			return false;
		}

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
			print::debugln("EnablePrivilege - AdjustTokenPrivileges failed. Err: {}", GetLastError());
			return false;
		}

		CloseHandle(hToken);

		return true;
	}

	void clear_process(DWORD PID, std::wstring str) {

		if (str.empty()) return;

		HANDLE ppl = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID);
		if (!ppl) {
			return;
		}

		std::wstring proc = GetProcessName(PID);
		PROCESS_PROTECTION_LEVEL_INFORMATION ppli{};

		if (GetProcessInformation(ppl, ProcessProtectionLevelInfo, &ppli, sizeof(ppli))) {
			if (ppli.ProtectionLevel < 6) {
				wprint::infolnl(L"Skipping {} due to protection", proc);
				CloseHandle(ppl);
				return;
			}
		}
		CloseHandle(ppl);


		HANDLE h = nullptr;
		CLIENT_ID cid{};
		OBJECT_ATTRIBUTES objAttr{};

		RtlSecureZeroMemory(&objAttr, sizeof(OBJECT_ATTRIBUTES));
		objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

		RtlSecureZeroMemory(&cid, sizeof(CLIENT_ID));
		cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(PID));

		NTSTATUS status = NtOpenProcess(
			&h,
			PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
			&objAttr,
			&cid
		);

		if (!NT_SUCCESS(status)) {
			wprint::errorln(L"Failed to clean {}.", proc);
			return;
		}

		wprint::successlnl(L"Cleaning {}", proc);

		MEMORY_BASIC_INFORMATION m{};
		SYSTEM_INFO si{};
		GetSystemInfo(&si);

		uintptr_t addr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
		uintptr_t end  = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

		std::string ASCII(str.begin(), str.end());

		while (addr < end) {
			NTSTATUS ntquery = NtQueryVirtualMemory(h, reinterpret_cast<PVOID>(addr), MemoryBasicInformation, &m, sizeof(m), nullptr);

			if (!NT_SUCCESS(ntquery)) {
				addr += m.RegionSize;
				continue;
			}

			if (m.State == MEM_COMMIT &&
				(m.Protect == PAGE_READWRITE || m.Protect == PAGE_EXECUTE_READWRITE) &&
				!(m.Protect & PAGE_GUARD)) {

				std::unique_ptr<BYTE[]> buf = std::make_unique<BYTE[]>(m.RegionSize);
				SIZE_T bytesRead{};

				NTSTATUS ntread = NtReadVirtualMemory(h, reinterpret_cast<PVOID>(addr), buf.get(), m.RegionSize, &bytesRead);

				if (NT_SUCCESS(ntread)) {
					for (SIZE_T i = 0; i <= bytesRead - str.size(); ++i) {

						bool wide  =          memcmp(buf.get() + i, str.data(), str.size())     == 0;
						bool ascii = !wide && memcmp(buf.get() + i, ASCII.data(), ASCII.size()) == 0;

						if (wide || ascii) {
							uintptr_t offset = addr + i;
							wprint::infolnl(L"[{}] - String '{}' found at {:#x}.", proc, str, offset);

							SIZE_T uwu = ascii ? ASCII.size() : str.size() * sizeof(wchar_t);

							std::unique_ptr<BYTE[]> RtlNull = std::make_unique<BYTE[]>(uwu);
							RtlSecureZeroMemory(RtlNull.get(), uwu);

							NTSTATUS ntwrite = NtWriteVirtualMemory(h, reinterpret_cast<PVOID>(offset), RtlNull.get(), uwu, nullptr);

							if (NT_SUCCESS(ntwrite)) {
								wprint::successlnl(L"Cleaned.");
							}
							else {
								wprint::errorlnl(L"Failed to clean.");
								wprint::debuglnl(L"NTSTATUS: {:#x}", ntwrite);
							}
						}

					}
				}
			}

			addr += m.RegionSize;
		}
		wprint::nrml(L"\n");
		wprint::successlnl(L"Finished cleaning {}.", proc);
		NtClose(h);
	}


}