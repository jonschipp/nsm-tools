#!/usr/bin/env python
import json
import urllib
import urllib2
import sys

apikey = ''

def usage():
  print '''Submit hash to virtus-total
Usage: %s <hash>''' % sys.argv[0]
  exit(0)

def collect(data):
  retrieve             = data[0]
  sha1                 = retrieve['sha1']
  filenames            = retrieve['filenames']
  first_seen           = retrieve['first-seen']
  last_seen            = retrieve['last-seen']
  last_scan_permalink  = retrieve['last-scan-permalink']
  return sha1, filenames, first_seen, last_seen, last_scan_permalink

def msg(sha1, filenames, first_seen, last_seen, last_scan_permalink):
  print '''===Suspected Malware Item===
  SHA1: %s
  Filenames: %s
  First Seen: %s
  Last Seen: %s
  Link: %s''' % (sha1, filenames, first_seen, last_seen, last_scan_permalink)

def in_database(data, mhash):
  result = data[0]['result']
  if result == 0: 
    return False
  return True

def arguments():
  if len(sys.argv) < 2:
    usage()
  if '-h' in sys.argv[1]:
    usage()
  if not apikey:
    print "Set apikey in %s to value of your Virus Total key" % sys.argv[0]
    exit(1)

  mhash = sys.argv[1]
  return mhash

def query_api(mhash, apikey):
  url = "http://api.vtapi.net/vtapi/get_file_infos.json"
  parameters = {"resources": mhash, "apikey": apikey}
  encoded = urllib.urlencode(parameters)
  req = urllib2.Request(url, encoded)
  response = urllib2.urlopen(req)
  response_string = response.read()
  data = json.loads(response_string)
  return data

mhash = arguments()
data = query_api(mhash, apikey)

if not in_database(data, mhash):
  print 'No entry for %s in database' % mhash
  exit(1)

# Positive match found
sha1, filenames, first_seen, last_seen, last_scan_permalink = collect(data)
msg(sha1, filenames, first_seen, last_seen, last_scan_permalink)
exit(1)
