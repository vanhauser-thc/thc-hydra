## thc-hydra
### How to compile hydra on Android

Hydra can run on Android without root permissions,
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

To use xhydra, you will need to install a graphical output in termux, you can be guided from this article:

[https://wiki.termux.com/wiki/Graphical_Environment](https://wiki.termux.com/wiki/Graphical_Environment)

If you have never used a GUI on Android or are not able to configure it, 
you can use these projects from the termux community:

- [openbox by adi1090x](https://github.com/adi1090x/termux-desktop) 

- [lxqt by yisus](https://github.com/Yisus7u7/termux-desktop-lxqt)

- [xfce4 by yisus](https://github.com/Yisus7u7/termux-desktop-xfce) 
