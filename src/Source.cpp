/**
* This example project is meant to be injected into "victim.exe" provided in the hookftw_example/target folder in this repository. 
* Debug symbols of "victim.exe" are also provided.
* The project demonstrates all available hooking techniques in hookFTW.
* 
* !! compile in 64 bit !!
* 
*/

#include <cstdio>
#include <Windows.h>

#include "Detour.h"
#include "MidfunctionHook.h"
#include "IATHook.h"
#include "VFTHook.h"
#include "VEHHook.h"

#include "DbgSymbols.h"


// type definition of GetModuleHandleA function (MSDN)
using getModuleHandleAFunction = HMODULE(WINAPI*)(LPCSTR lpModuleName);
getModuleHandleAFunction originalGetModuleHandleA;

// compiler ignored __cdecl keyword and made is fastcall anyway
using cdeclCallFunction = int(__fastcall*)(int x, int y, int );
cdeclCallFunction originalCdeclCallFunction;

HMODULE WINAPI hookedGetModuleHandleA(LPCSTR lpModuleName)
{
	printf("\tGetModuleHandleA was called!\n");

	// call original GetModuleHandleA function
	return originalGetModuleHandleA(lpModuleName);
}

void hookedCow()
{
	printf("\t[Cow] - hooked - makes muuuh\n");
}

int hookedCalculate(int x)
{
	printf("\tcalculate called, returning %d\n", x);
	return x;
}

int __fastcall hookedCdeclCallFunc(int x, int y, int z)
{
	printf("\tcdeclCallFunc called, returning twice the original result\n");
	return 2 * originalCdeclCallFunction(x,y,z);
}

DWORD __stdcall Run(LPVOID hModule)
{
	int8_t* baseAddress = (int8_t*)GetModuleHandle(NULL);

	// byte patching at the beginning of the function
	hookftw::Detour detourHook;
	(cdeclCallFunction)originalCdeclCallFunction = (cdeclCallFunction)detourHook.Hook(baseAddress + 0x1B60, (int8_t*)hookedCdeclCallFunc);


	// byte patching at the beginning of the function
	hookftw::MidfunctionHook midfunctionHook;
	midfunctionHook.Hook(
		baseAddress + 0x1B20,
		[](hookftw::context* ctx) {
			// print registers
			ctx->PrintRegister();	

			// modify return value to the result of a call of the function with different parameters
			ctx->rax = ctx->CallOriginal<int>(hookftw::CallingConvention::fastcall_call, 2, 3, 5);

			// skip original invocation of function
			ctx->SkipOriginalFunction();
		}
	);

	// import address table hook
	hookftw::IATHook iatHook;
	originalGetModuleHandleA = (getModuleHandleAFunction)iatHook.Hook("Kernel32.dll", "GetModuleHandleA", (int8_t*)hookedGetModuleHandleA);

	// use dbgsymbols (.pdb file) to resolve virtual function table of Cow class
	hookftw::DbgSymbols dbgSymbols;
	// hook the first virtual method of the Cow class
	hookftw::VFTHook vftHook((int8_t**)dbgSymbols.GetAddressBySymbolName("Cow::`vftable'"));
	vftHook.Hook(0, (int8_t*)hookedCow);

	// vectored exception ahndler hook
	hookftw::VEHHook vehHook;
	vehHook.Hook(baseAddress + 0x1AA0, (int8_t*)hookedCalculate);

	while (true)
	{
		// press F1 to unhook all hooks
		if (GetAsyncKeyState(VK_F1) & 0x1)
		{
			detourHook.Unhook();
			midfunctionHook.Unhook();
			iatHook.Unhook();
			vftHook.Unhook();
			vehHook.Unhook();
			printf("~~~ Unhooked all functions ~~~~\n");
			break;
		}
		Sleep(1);
	}

	// clean up. All hooks have to be removed at this point or the target application will crash.
	FreeLibraryAndExitThread(static_cast<HMODULE>(hModule), 0);
	return TRUE;
}

BOOL __stdcall DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		CreateThread(nullptr, 0, Run, hModule, 0, nullptr);
		break;
	case DLL_PROCESS_DETACH:
		break;
	default:
		break;
	}
	return TRUE;
}