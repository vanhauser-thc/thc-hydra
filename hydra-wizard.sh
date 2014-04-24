#!/bin/sh
#
# based on a script by Shivang Desai <shivang.ice.2010@gmail.com>
#
echo
echo "Welcome to the Hydra Wizard"
echo
read -p "Enter the service to attack (eg: ftp, ssh, http-post-form): " service
test -z "$service" && { echo Error: service may not be empty ; exit 1 ; }
read -p "Enter the the target to attack (or filename with targets): " target
test -z "$target" && { echo Error: target may not be empty ; exit 1 ; }
read -p "Enter a username to test or a filename: " user
test -z "$user" && { echo Error: user may not be empty ; exit 1 ; }
read -p "Enter a password to test or a filename: " pass
test -z "$pass" && { echo Error: pass may not be empty ; exit 1 ; }
read -p "If you want to test for passwords (s)ame as login, (n)ull or (r)everse login, enter these letters without spaces (e.g. \"sr\") or leave empty otherwise: " pw
read -p "Port number (press enter for default): " port
echo
echo The following options are supported by the service module:
hydra -U $service
echo
read -p "If you want to add module options, enter them here (or leave empty): " opt
echo

ports=""
pws=""
opts=""
test -e "$target" && targets="-M $target"
test -e "$target" || targets="$target"
test -e "$user" && users="-L $user"
test -e "$user" || users="-l $user"
test -e "$pass" && passs="-P $pass"
test -e "$pass" || passs="-p $pass"
test -n "$port" && ports="-s $port"
test -n "$pw" && pws="-e $pw"
test -n "$opt" && opts="-m '$opt'"

echo The following command will be executed now:
echo " hydra $users $passs -u $pws $ports $opts $targets $service"
echo
read -p "Do you want to run the command now? [Y/n] " yn
test "$yn" = "n" -o "$yn" = "N" && { echo Exiting. ; exit 0 ; }
echo
hydra $users $passs -u $pws $ports $opts $targets $service
