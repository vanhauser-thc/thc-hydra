#!/bin/sh
#
# Name:     dpl4hydra
# Version:  0.9.9
# Date:     2012-04-16
# Author:   Roland Kessler / Twitter: @rokessler
# Synopsis: Generates a (d)efault (p)assword (l)ist as input for THC hydra.
# Credits:  Thanks to van Hauser for support and fixing portability issues.
#           "The universe is an intelligence test." -Timothy Leary (R.I.P.)

INSTALLDIR=/usr/local
LOCATION=etc

usage ()
{
cat <<EOF
dpl4hydra v0.9.9 (c) 2012 by Roland Kessler (@rokessler)

Syntax: `basename $0` [help] | [refresh] | [BRAND] | [all]

This script depends on a local (d)efault (p)assword (l)ist called
${FULLFILE}. If it is not available, regenerate it with
'`basename $0` refresh'. Source of the default password list is
$SITE

Options:
  help        Help: Show this message
  refresh     Refresh list: Download the full (d)efault (p)assword (l)ist
              and generate a new local ${FULLFILE} file. Takes time!
  BRAND       Generates a (d)efault (p)assword (l)ist from the local file
              ${FULLFILE}, limiting the output to BRAND systems, using
              the format username:password (as required by THC hydra).
              The output file is called dpl4hydra_BRAND.lst.
  all         Dump list of all systems credentials into dpl4hydra_all.lst.

Example:
# `basename $0` linksys
File dpl4hydra_linksys.lst was created with 20 entries.
# hydra -C ./dpl4hydra_linksys.lst -t 1 192.168.1.1 http-get /index.asp
EOF
}

refresh ()
{
  echo
  echo "Trying to locate wget or curl... " | tr -d "\n"
  which wget >/dev/null 2>&1 && FETCH="wget -q -O -"
  which curl >/dev/null 2>&1 && FETCH="curl -s"

  if [ -n "$FETCH" ]; then
    echo "done."
    echo "Using `echo $FETCH | cut -d ' ' -f 1` for downloading data."
    echo
  else
    echo
    echo "ERROR: Cannot refresh the list without wget or curl. Aborting." >&2
    echo
    exit 1
  fi
  
  echo "Trying to download list of vendors from"
  echo "${SITE}... " | tr -d "\n"
  $FETCH $SITE > $INDEXSITE 2>/dev/null || { echo; echo; echo "ERROR: Downloading data to disk failed. Network down?" >&2; echo; rm $INDEXSITE; exit 1; }
  echo "done."
  echo
  
  cat $INDEXSITE | grep -i 'href=./passwd-' | sed 's/.*href=.\/passwd-/\/passwd-/' | sed 's/".*//' > $SUBSITES
  rm $INDEXSITE
  
  if [ -r $FULLFILE ]; then
    echo "Moving existing password list to ${OLDFILE}."
    echo
    mv $FULLFILE $OLDFILE || { echo "ERROR: Moving file $FULLFILE failed. Please check." >&2; echo; exit 1; }
  fi
    
  for SUBSITE in `cat $SUBSITES`; do
    VENDOR=`echo $SUBSITE | sed 's/\.htm*//' | sed 's/.*-//'`
    echo "Downloading default passwords for ${VENDOR} ... " | tr -d "\n"
    $FETCH "${SITE}${SUBSITE}" | tr -d '\n\r' | sed 's/<tr/\n/gi' | sed 's/<\/tr/\n/gi' | \
      grep -iw celltext | sed 's/.*celltext">/,/i' | sed 's/<\/td>/,/g' | sed 's/<[a-z =/":;-]*>//gi' | \
      sed 's/[\t ]*,[\t ]*/,/g' | sed 's/&[a-z]*;//gi' | sed 's/(unknown)//gi' | sed 's/(none)//gi' | sed 's/,unknown,/,,/gi' | sed 's/,none,/,,/gi' > dpl4hydra_${VENDOR}.tmp

    cat dpl4hydra_${VENDOR}.tmp | awk -F, '{print"'$VENDOR',"$2","$3","$4","$5","$6","$7","$8","$9}' >> $FULLFILE
    
    rm dpl4hydra_${VENDOR}.tmp
    echo "done."
  done
  rm $SUBSITES
  
  if [ ! -r $LOCALFILE ]; then
    echo
    echo "ERROR: Cannot access local file ${LOCALFILE}. Skipping." >&2
    echo
  else
    echo
    echo "Merging download with ${LOCALFILE}... " | tr -d "\n"
    cat $LOCALFILE >> $FULLFILE || { echo; echo "ERROR: Merging of $FULLFILE and $LOCALFILE failed. Please check." >&2; echo; exit 1; }
    echo "done."
  fi
  
  echo "Cleaning up and sorting ${FULLFILE}... " | tr -d "\n"
  cat $FULLFILE | sed 's/(null)//g' | sed 's/(Null)//g' | sed 's/(NULL)//g' | sed 's/(blank)//g' | sed 's/(Blank)//g' | sed 's/(BLANK)//g' | sed 's/(none)//g' | sed 's/(None)//g' | sed 's/(NONE)//g' | sed 's/none//g' | sed 's/n\/a//g' | sed 's/&lt;/</g' | sed 's/&gt;/>/g' | sed 's/&nbsp;//g' | sort | uniq > $CLEANFILE
  mv $CLEANFILE $FULLFILE
  echo "done."
  echo
  echo "Refreshed (d)efault (p)assword (l)ist $FULLFILE"
  echo "was created with `wc -l $FULLFILE | awk '{ print $1 }'` entries."
  echo
}

generate ()
{
  HYDRAFILE=`echo "dpl4hydra_${BRAND}.lst" | tr '/ =:@\\|;<>"'"'" '_____________'`

  if [ ! -r $FULLFILE ]; then
    echo
    echo "ERROR: Cannot access input file ${FULLFILE}" >&2
    echo "       You can rebuild it with '`basename $0` refresh'." >&2
    echo
    echo "       Trying to use $LOCALFILE instead... " | tr -d "\n"
    if [ -r $LOCALFILE ]; then
      FULLFILE=$LOCALFILE
      echo "done."
    else
      echo
      echo "ERROR: Cannot access local file ${LOCALFILE}. Aborting." >&2
      echo
      exit 1
    fi
  fi

  cat $FULLFILE 2>/dev/null | grep -i "$PATTERN" | awk -F"," '{ print $5":"$6 }' | sed 's/^[ \t]*//' | sed 's/[ \t]*$//' | sort | uniq > $HYDRAFILE

  ENTRIES=`wc -l $HYDRAFILE | awk '{ print $1 }'`
  if [ "$ENTRIES" -eq 0 ]; then
    rm -f $HYDRAFILE
    echo
    echo "ERROR: No matching entries found for $BRAND systems." >&2
    echo "       File $HYDRAFILE was not created." >&2
    echo
    exit 1
  else
    if [ "$ENTRIES" -eq 1 ]; then
      echo
      echo "File $HYDRAFILE was created with one entry."
      echo
    else
      echo
      echo "File $HYDRAFILE was created with $ENTRIES entries."
      echo
    fi
  fi
}

LC_ALL=C
export LC_ALL
DPLPATH="."
test -r "$DPLPATH/dpl4hydra_full.csv" || DPLPATH="$INSTALLDIR/$LOCATION"
FULLFILE="$DPLPATH/dpl4hydra_full.csv"
OLDFILE="$DPLPATH/dpl4hydra_full.old"
LOCALFILE="$DPLPATH/dpl4hydra_local.csv"
INDEXSITE="$DPLPATH/dpl4hydra_index.tmp"
SUBSITES="$DPLPATH/dpl4hydra_subs.tmp"
CLEANFILE="$DPLPATH/dpl4hydra_clean.tmp"
SITE="http://open-sez.me"

case $# in
	0) usage
	   exit 0;;
	1) OPT=`echo $1 | tr "[A-Z]" "[a-z]"`;;
	*) echo
     echo "ERROR: Too many options." >&2
     usage
     exit 1;;
esac

case "$OPT" in
  "-h" | "help" | "-help" | "--help")          usage;;
  "-r" | "refresh" | "-refresh" | "--refresh") refresh;;
  "-a" | "all" | "-all" | "--all")             PATTERN=","
                                               BRAND="all"
                                               generate;;
  *)                                           PATTERN="${OPT}"
                                               BRAND="$OPT"
                                               generate;;
esac
