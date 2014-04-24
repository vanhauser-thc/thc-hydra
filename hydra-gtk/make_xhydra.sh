#!/bin/bash
PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/opt/gnome/lib/pkgconfig
export PKG_CONFIG_PATH
echo "Trying to compile xhydra now (hydra gtk gui) - dont worry if this fails, this is really optional ..."
./configure > /dev/null 2> errors
test -e Makefile || {
  echo "Error: configure wasnt happy. Analyse this:"
  cat errors
  exit 1
}
make > /dev/null 2> errors
test -e src/xhydra || {
  echo "Error: could not compile. Analyse this:"
  cat errors
  echo
  echo 'Do not worry, as I said, xhydra is really optional. ./hydra is ready to go!'
  exit 0
}
cp -v src/xhydra ..
echo "The GTK GUI is ready, type \"./xhydra\" to start"
