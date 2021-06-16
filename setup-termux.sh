#!/bin/bash
#this script will configure hydra in termux

TERMUX_PREFIX="/data/data/com.termux/files/usr"

#required dependencies 

pkg update && pkg upgrade 
pkg install -y x11-repo
pkg install -y clang make openssl openssl-tool wget openssh coreutils gtk2 gtk3

#compile hydra 

./configure --prefix=$TERMUX_PREFIX
make
make install

