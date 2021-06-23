![hookftw banner](img/hookftw_banner.png)
# Example project
This project shows how to include hookFTW as a git submodule and using CMAKE to build it.

## Setting up hookFTW yourself
Getting hookftw
1. Clone hookftw repository including submodules (zydis is included in hookFTW as a submodule):
   git clone --recursive https://git.fslab.de/fstotz2s/hookftw.git
2. Build hookFTW
3. Include headers: hookftw/library/src
4. Link hookftw:	hookftw\out\build\x86-Debug\library\hookftw.lib
5. Link zydis: 		hookftw\out\build\x86-Debug\deps\zydis\Zydis.lib