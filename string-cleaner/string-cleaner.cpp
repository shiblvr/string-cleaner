#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>
#include <unordered_map>
#include <thread>

#include <print.hpp>
#include <util.hpp>


__forceinline std::wstring trim(std::wstring& str) {
	return str = str.substr(str.find_first_not_of(L' '), str.find_last_not_of(L' ') - str.find_first_not_of(L' ') + 1);
}

__forceinline bool is_num(const std::wstring& str) {
	return !str.empty() && std::all_of(str.begin(), str.end(), iswdigit);
}
int main()
{

	if (NtQueryVirtualMemory == nullptr || NtReadVirtualMemory == nullptr || NtWriteVirtualMemory == nullptr
		|| NtClose == nullptr || NtOpenProcess == nullptr) {
		print::errorln("Failed to load ntdll functions");
		std::cin.get();
		return 1;
	}

	if (!u::is_admin()) {
		print::infoln("Program is recommended to be ran as administrator due to some processes not being accessible as user.");

	}
	else
	{
		if (!u::enable_privilege(SE_DEBUG_NAME)) {
			print::errorln("Failed to enable the privilege for debugging, some processes may not be accessible.");
		}
		else {

			if (!u::is_system()) {

				if (!u::steal_sys_token()) {

					print::successln("Running as administrator");
				}
				else {

					ExitProcess(0);
				}
			}
			else {

			print::successln("Running as SYSTEM");

			}
		}
	}

	std::unordered_map<std::wstring, DWORD> x{};
	std::unordered_set<std::wstring> n{};


	std::wstring procName;
	print::infoln("Enter a list of process names or PIDs separated by a comma (example: notepad.exe, 1234): \n");
	std::getline(std::wcin, procName);
	std::wstringstream procList(procName);


	while (std::getline(procList, procName, L',')) {
		
		procName = trim(procName);
		DWORD PID = u::get_process_id(procName.c_str());

		if (PID != 0) {
			x.insert({ procName, PID });
		}
		else
		{
			if (is_num(procName)) {
				DWORD PID = std::stoul(procName);
				
				HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, PID);
				
				if (!hProc) {

					wprint::errorln(L"Invalid PID: {} ", procName);
					continue;

				}
				
				CloseHandle(hProc);
				
				std::wstring procName = u::GetProcessName(PID);
				x.insert({ procName, PID});
			}
			wprint::errorln(L"Invalid process: {} ", procName);
		}
	}

	std::wstring str2clean;
	std::println();
	print::infoln("Enter a strings to clean seperated by a comma (string1, string2): \n");
	std::getline(std::wcin, str2clean);
	std::wstringstream wss(str2clean);

	while (std::getline(wss, str2clean, L',')) {
		str2clean = trim(str2clean);
		n.insert(str2clean);
	}
	
	system("cls");
	
	for (const auto& z : x) {
		wprint::infoln(L"Cleaning {}: {}", z.first, z.second);
	}

	wprint::info(L"Strings to be cleaned: ");
	for (const auto & z : n) {
		std::wcout << z << L", ";
	}

	std::string q{};

	std::println("\nIs this correct? (Y/N)");

	if (std::getline(std::cin, q) && (q == "Y" || q == "y")) {
		for (const auto & z : x) {
			for (const auto& nr : n) {
				std::thread(u::clear_process, z.second, nr).detach();
			}
		}
	}
	else {
		ExitProcess(0);
	}

	std::cin.get();
	return 0;
}
