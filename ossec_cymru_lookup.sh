#!/usr/bin/env bash
# Author: Jon Schipp
CHAT=/usr/local/bin/ircsay
PROG=OSSEC
SCRIPT=$0
CHANNEL="#ossec-syscheck"
MAIL=you@org
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
OSSEC Hash Lookup
- Malware found!

"$alert"

Location: $HOSTNAME $PWD/$0
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
result=$(timeout 1s dig +short ${sha1}.malware.hash.cymru.com A)

# Alert or exit
[[ "$result" == '127.0.0.2' ]] && alert
die "No match found"
