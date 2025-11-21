#!/bin/sh

set -e

echo "Trying to compile xhydra now (hydra gtk gui)"
./configure
make
cp -v src/xhydra ..
echo "The GTK GUI is ready, type \"./xhydra\" to start"
