#!/usr/bin/env bash
# Author: Jon Schipp
CHAT=/usr/local/bin/ircsay
PROG=OSSEC
SCRIPT=$0
CHANNEL="#alerts"
MAIL=user@org
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5

die(){
  if [ -f ${COWSAY:-none} ]; then
    $COWSAY -d "$*"
  else
    printf "$(date) $*\n" >> virustotal_lookup.log
  fi
  exit 1
}

check_args(){
  local argc
  argc="$1"
  [[ $argc -ge 5 ]] || die "Not enough arguments given"
}

msg(){
cat <<EOF
OSSEC Virus Total Lookup
- Malware found!

"$RESULTS"

"$ALERT"

Location: $HOSTNAME $SCRIPT
EOF
}

alert(){
  msg | mail -s "[sa] [${PROG}] $SCRIPT" $MAIL
  msg | $CHAT "$CHANNEL" -
}

get_alert(){
  local alert
  alert=$(awk -v ts=$ALERTID 'BEGIN { RS=""; ORS="\n" } $0 ~ ts { print }' ${PWD}/../logs/alerts/alerts.log)
  [[ "$alert" ]] || die "No alert found matching timestamp"
  echo "$alert"
}

is_hash(){
  local sha1
  sha1="$1"
  [[ $sha1 ]] || "Hash variable empty"
  [[ $sha1 =~ ^\ +$ ]] && die "Hash variable is only whitespace"
}

get_hash_from_alert(){
  local alert
  local sha1
  alert="$@"
  sha1=$(printf "$alert\n" | grep -o '[a-zA-Z0-9]\{40\}' | tail -n 1)
  is_hash "$sha1"
  echo "$sha1"
}

get_hash_from_filename(){
  local alert
  local sha1
  alert="$@"
  file=$(printf "$alert\n" | awk -F "['']" '/^File|changed for:/ { print $2 }')
  [[ -r "$file" ]] || die "File not available on system"
  sha1=$(sha1sum $file | grep -o '[a-zA-Z0-9]\{40\}')
  is_hash "$sha1"
  echo "$sha1"
}

virus_lookup(){
   local sha1
   local results
   sha1="$1"
   results=$($PWD/bin/virus_total.py $sha1)
   status_code=$?
   echo "$results"
   return $status_code
}

# Check for arguments
check_args $#

# Check for chat program
[[ -f $CHAT ]] || exit 1

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)

# Logging the call
printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" >> ${PWD}/../logs/active-responses.log

# Getting full alert
ALERT=$(get_alert)

# Obtain hash
[[ $RULEID -eq 554 ]] && HASH=$(get_hash_from_filename "$ALERT") || HASH=$(get_hash_from_alert "$ALERT")

# Lookup
RESULTS=$(virus_lookup $HASH) || die "No malware found"

# Notify contacts
alert
