# nsm-tools
Various tools and integrations to be used in NSM

### virus_total.py

Query VirusTotal API by hash
```
$ ./virus_total.py 99017f6eebbac24f351415dd410d522d
===Suspected Malware Item===
  SHA1: 4d1740485713a2ab3a4f5822a01f645fe8387f92
  Filenames: [u'nuevo4', u'nuevo4.exe', u'vti-rescan', u'52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c', u'nuevo4.exe-73yTyF', u'C:\test.exe']
  First Seen: 2010-04-10 09:34:59
  Last Seen: 2015-03-26 13:28:54
  Link: https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1449484829/
```

Place your apikey to use the tool
```
$ grep apikey ./virus_total.py
apikey = 'your_api_key'
```

### OSSEC Team Cymru Lookup

For use with OSSEC, hashes are grabbed from syscheck alerts (FIM) and sent to the Team Cymru Malware Hash Registry.
Place script in `$OSSEC/active-response/bin/`.

```
  <command>
    <name>cymru_lookup</name>
    <executable>ossec_cymru_lookup.sh</executable>
    <expect></expect>
  </command>

  <active-response>
    <command>cymru_lookup</command>
    <location>server</location>
    <rules_group>syscheck</rules_group>
  </active-response>
```

Try it manually
```
./ossec_cymru_lookup.sh $(grep syscheck /var/ossec/logs/active-responses.log | tail -n 1 | cut -d " " -f9-)
No match found
```

### OSSEC Virus Totol Lookup

Same as above but for Virus Total. It's a wrapper for `virus_total.py`.
Place them both in `$OSSEC/active-response/bin` and update the configs in the example above.
