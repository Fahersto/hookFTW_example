#include <cstdio>

#include "MidfunctionHook.h"

int square(int x)
{
	return x * x;
}


int main()
{
	int x = 10;
	printf("square of %d is %d\n", x, square(x));

	int8_t* aslr = (int8_t*)GetModuleHandle(NULL);
	hookftw::MidfunctionHook squareHook;
	squareHook.Hook(aslr+ 0x2000,
		[](hookftw::context* ctx) {

			// change first parameter to 7 (fastcall)
			ctx->rcx = 7;
		}
	);

	printf("square of %d is %d\n", x, square(x));
}