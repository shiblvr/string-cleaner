#pragma once

#include <print>
#include <Windows.h>
#include <iostream>
#include <mutex>
#include <format>


#define GREEN  2
#define RED    4
#define WHITE  7
#define PURPLE 5
#define YELLOW 14

namespace print {

	inline std::mutex mutex;

	inline void SetColor(int color) {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
	}

	template<typename... _Types>
	void errorln(const std::format_string<_Types...> _Fmt, _Types&&... _Args) {
		std::print("[");
		SetColor(RED);
		std::print("-");
		SetColor(WHITE);
		std::print("] ");
		std::println(stderr, _Fmt, std::forward<_Types>(_Args)...);
	}


	template<typename... _Types>
	void error(const std::format_string<_Types...> _Fmt, _Types&&... _Args) {
		std::print("[");
		SetColor(RED);
		std::print("-");
		SetColor(WHITE);
		std::print("] ");
		std::print(_Fmt, std::forward<_Types>(_Args)...);
	}

	template<typename... _Types>
	void infoln(const std::format_string<_Types...> _Fmt, _Types&&... _Args) {
		std::print("[");
		SetColor(PURPLE);
		std::print("*");
		SetColor(WHITE);
		std::print("] ");
		std::println(_Fmt, std::forward<_Types>(_Args)...);
	}

	template<typename... _Types>
	void successln(const std::format_string<_Types...> _Fmt, _Types&&... _Args) {
		std::print("[");
		SetColor(GREEN);
		std::print("+");
		SetColor(WHITE);
		std::print("] ");
		std::println(_Fmt, std::forward<_Types>(_Args)...);
	}

	template<typename... _Types>
	void debugln(const std::format_string<_Types...> _Fmt, _Types&&... _Args) {
#ifdef _DEBUG
		std::print("[");
		SetColor(YELLOW);
		std::print("DEBUG");
		SetColor(WHITE);
		std::print("]");
		SetColor(YELLOW);
		std::print(": ");
		SetColor(WHITE);
		std::println(_Fmt, std::forward<_Types>(_Args)...);
#endif
	}

	template<typename... _Types>
	void info(const std::format_string<_Types...> _Fmt, _Types&&... _Args) {
		std::print("[");
		SetColor(PURPLE);
		std::print("*");
		SetColor(WHITE);
		std::print("] ");
		std::print(_Fmt, std::forward<_Types>(_Args)...);
	}
	void success();
};

namespace wprint {

	inline std::mutex mutex;

	inline void SetColor(int color) {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
	}

	template<typename... _Types>
	void errorln(std::wstring_view _Fmt, _Types&&... _Args) {
		std::wcout << L"[";
		SetColor(RED);
		std::wcout << L"-";
		SetColor(WHITE);
		std::wcout << L"] ";

		std::wcout << std::vformat(_Fmt, std::make_wformat_args(std::forward<_Types>(_Args)...)) << L'\n';
	}
	template<typename... _Types>

	void info(std::wstring_view _Fmt, _Types&&... _Args) {
		std::wcout << L"[";
		SetColor(PURPLE);
		std::wcout << L"*";
		SetColor(WHITE);
		std::wcout << L"] ";

		std::wcout << std::vformat(_Fmt, std::make_wformat_args(std::forward<_Types>(_Args)...));
	}
	template<typename... _Types>

	void successln(std::wstring_view _Fmt, _Types&&... _Args) {
		std::wcout << L"[";
		SetColor(GREEN);
		std::wcout << L"+";
		SetColor(WHITE);
		std::wcout << L"] ";

		std::wcout << std::vformat(_Fmt, std::make_wformat_args(std::forward<_Types>(_Args)...)) << L'\n';
	}

	template<typename... _Types>

	void successlnl(std::wstring_view _Fmt, _Types&&... _Args) {
		std::lock_guard lock(mutex);
		std::wcout << L"[";
		SetColor(GREEN);
		std::wcout << L"+";
		SetColor(WHITE);
		std::wcout << L"] ";

		std::wcout << std::vformat(_Fmt, std::make_wformat_args(std::forward<_Types>(_Args)...)) << L'\n';
	}

	template<typename... _Types>


	void successl(std::wstring_view _Fmt, _Types&&... _Args) {
		std::lock_guard lock(mutex);
		std::wcout << L"[";
		SetColor(GREEN);
		std::wcout << L"+";
		SetColor(WHITE);
		std::wcout << L"] ";

		std::wcout << std::vformat(_Fmt, std::make_wformat_args(std::forward<_Types>(_Args)...));
	}
	
	template<typename... _Types>
	void infol (std::wstring_view _Fmt, _Types&&... _Args) {
		std::lock_guard lock(mutex);
		std::wcout << L"[";
		SetColor(PURPLE);
		std::wcout << L"*";
		SetColor(WHITE);
		std::wcout << L"] ";

		std::wcout << std::vformat(_Fmt, std::make_wformat_args(std::forward<_Types>(_Args)...));
	}

	template<typename... _Types>
	void errorlnl(std::wstring_view _Fmt, _Types&&... _Args) {
		std::lock_guard lock(mutex);
		std::wcout << L"[";
		SetColor(RED);
		std::wcout << L"-";
		SetColor(WHITE);
		std::wcout << L"] ";

		std::wcout << std::vformat(_Fmt, std::make_wformat_args(std::forward<_Types>(_Args)...)) << L'\n';
	}

	template<typename... _Types>
	void infolnl(std::wstring_view _Fmt, _Types&&... _Args) {
		std::lock_guard lock(mutex);
		std::wcout << L"[";
		SetColor(PURPLE);
		std::wcout << L"*";
		SetColor(WHITE);
		std::wcout << L"] ";

		std::wcout << std::vformat(_Fmt, std::make_wformat_args(std::forward<_Types>(_Args)...)) << L'\n';
	}

	template<typename... _Types>
	void infoln(std::wstring_view _Fmt, _Types&&... _Args) {
		std::wcout << L"[";
		SetColor(PURPLE);
		std::wcout << L"*";
		SetColor(WHITE);
		std::wcout << L"] ";
		
		std::wcout << std::vformat(_Fmt, std::make_wformat_args(std::forward<_Types>(_Args)...)) << L'\n';
	}

	template<typename... _Types>
	void debuglnl(std::wstring_view _Fmt, _Types&&... _Args) {
		std::lock_guard lock(mutex);
		std::wcout << L"[";
		SetColor(YELLOW);
		std::wcout << L"DEBUG";
		SetColor(WHITE);
		std::wcout << L"] ";
		SetColor(YELLOW);
		std::wcout << L": ";
		SetColor(WHITE);

		std::wcout << std::vformat(_Fmt, std::make_wformat_args(std::forward<_Types>(_Args)...)) << L'\n';
	}

	template<typename... _Types>
	void nrml(std::wstring_view _Fmt, _Types&&... _Args) {
		std::lock_guard lock(mutex);

		std::wcout << std::vformat(_Fmt, std::make_wformat_args(std::forward<_Types>(_Args)...));
	}

	template<typename... _Types>
	void nrm(std::wstring_view _Fmt, _Types&&... _Args) {

		std::wcout << std::vformat(_Fmt, std::make_wformat_args(std::forward<_Types>(_Args)...));
	}


}

