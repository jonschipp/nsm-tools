#!/usr/bin/env bash
# Author: Jon Schipp
CHAT=/usr/local/bin/ircsay
PROG=OSSEC
SCRIPT=$0
CHANNEL="#alerts"
MAIL=you@org
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5

# This scripts calls others because only one can be executed by OSSEC

die(){
  if [ -f ${COWSAY:-none} ]; then
    $COWSAY -d "$*"
  else
    printf "$*\n"
  fi
  exit 0
}

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)
CHAT="$PWD/bin/syscheck2chat.sh"
CYMRU="$PWD/bin/ossec_cymru_lookup.sh"
VT="$PWD/bin/virustotal_lookup.sh"

echo "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8" >> ${PWD}/../logs/active-responses.log

# Chat
[[ -x $CHAT ]] && $CHAT $1 $2 $3 $4 $5

# Cymru Hash Lookup
[[ -x $CYMRU ]] && $CYMRU $1 $2 $3 $4 $5

# Virus Total Hash Lookup
[[ -x $VT ]] && $VT $1 $2 $3 $4 $5
