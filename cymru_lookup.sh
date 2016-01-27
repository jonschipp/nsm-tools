#!/usr/bin/env bash
# Author: Jon Schipp
PRE="$(date +"%Y-%m-%dT%T.%6N%:z") $(hostname -s) $(basename $0):"
LOG="../logs/cymru_lookup.log"
AR_LOG="${PWD}/../logs/active-responses.log"
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5
AGENT=$6
SERVICE=$7
FILENAME=$8

die(){
  printf "$PRE $*\n" | tee -a $LOG
  exit 1
}

log(){
  printf "$PRE $*\n" | tee -a $LOG
  exit 0
}

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)

# Logging the call
[[ -f "$AR_LOG" ]] && printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" >> $AR_LOG

# Getting full alert
ALERT=$(awk -v ts=$ALERTID 'BEGIN { RS=""; ORS="\n" } $0 ~ ts { print }' ${PWD}/../logs/alerts/alerts.log)

# Obtain hash
SHA1=$(printf "$ALERT\n" | grep -o '[a-zA-Z0-9]\{40\}' | tail -n 1)
[[ $SHA1 ]] || die "ERROR: No hash found (${ALERTID:-empty})"

# Obtain other info for logging
[[ "$FILENAME" ]] || FILENAME=$(printf "$ALERT\n" | awk -F "['']" '/^File|changed for:/ { print $2 }')
[[ "$AGENT" ]]    || AGENT=$(printf "$ALERT\n" | awk -F "[()]" '/syscheck/ { print $2 }' | tail -n 1)

# Lookup
result=$(timeout 1s dig +short ${SHA1}.malware.hash.cymru.com A)

# Alert or exit
[[ "$result" =~ '127.0.0.' ]] && log "WARNING: Malicious hash found for ${FILENAME:-(empty)} ($SHA1) on ${AGENT:-(empty)}"
die "OK: No match found for ${FILENAME:-(empty)} ($SHA1) on ${AGENT:-(empty)}"
