## thc-hydra
### How to compile hydra on Android

Hydra is layers running on Android without rodent permission,
this is thanks to [Termux](https://termux.com/), A powerful emulator
of terminal with an ecosystem of packages. 

To compile hydra on Android, you will need to download 
[Termux](https://termux.com/). 

I note that termux no longer provides support
for Android devices less than or equal to Android 6,
therefore your cell phone must be Android 7 or higher. 

After installing termux, enter the following commands 
at your terminal:

```
# Update package list 
pkg update && pkg upgrade
# Installing dependencies
pkg install -y x11-repo
pkg install -y clang make openssl openssl-tool wget openssh coreutils gtk2 gtk3
# Compiling hydra
./configure --prefix=$PREFIX
make && make install 
```
