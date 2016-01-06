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
    printf "$*\n"
  fi
  exit 0
}

msg(){
cat <<EOF
OSSEC Virus Total Lookup
- Malware found!

"$results"

"$alert"

Location: $HOSTNAME $PWD/bin/$SCRIPT
EOF
}

alert(){
  msg | mail -s "[sa] [${PROG}] $SCRIPT" $MAIL
  msg | $CHAT "$CHANNEL" -
}

# Check for chat program
[[ -f $CHAT ]] || exit 1

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)

# Logging the call
printf "$(date) $0 $1 $2 $3 $4 $5 $6 $7 $8\n" >> ${PWD}/../logs/active-responses.log

# Getting full alert
alert=$(awk -v ts=$ALERTID 'BEGIN { RS=""; ORS="\n" } $0 ~ ts { print }' ${PWD}/../logs/alerts/alerts.log)

# Obtain hash
sha1=$(printf "$alert\n" | grep -o '[a-zA-Z0-9]\{40\}' | tail -n 1)
[[ $sha1 ]] || die "No hash found (was a syscheck alert given?)"

# Lookup
results=$($PWD/bin/virus_total.py $sha1)
[[ "$results" =~ "No entry"|"not malicious" ]] && die "$results"
alert
