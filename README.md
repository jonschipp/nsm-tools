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

### OSSEC RPM Lookup

`rpm_lookup.sh` is intended to be run on the OSSEC agents. On FIM alerts it will check the modified against the RPM database (using rpm verify).

```
 <command>
    <name>rpm_lookup</name>
    <executable>rpm_lookup.sh</executable>
    <expect>filename</expect>
  </command>

  <active-response>
    <command>rpm_lookup</command>
    <rules_group>syscheck,,</rules_group>
    <level>5</level>
    <location>local</location>
  </active-response>
```

### OSSEC AR Config All

1. Copy all scripts to /var/ossec/active-resposne/bin/

2. Enable active response for scripts
```
<command>
    <name>makelists</name>
    <executable>makelists.sh</executable>
    <expect>hostname</expect>
  </command>

  <command>
    <name>syscheck_all</name>
    <executable>syscheck-all.sh</executable>
    <expect>filename</expect>
  </command>

  <command>
    <name>ip_all</name>
    <executable>rule-all.sh</executable>
    <expect>srcip</expect>
  </command>

  <command>
    <name>rule_all</name>
    <executable>rule-all.sh</executable>
    <expect></expect>
  </command>

  <command>
    <name>rpm_lookup</name>
    <executable>rpm_lookup.sh</executable>
    <expect>filename</expect>
  </command>

  <active-response>
    <command>makelists</command>
    <rules_id>110000</rules_id>
    <location>server</location>
  </active-response>

  <active-response>
    <command>syscheck_all</command>
    <rules_group>syscheck,,</rules_group>
    <level>5</level>
    <location>server</location>
  </active-response>

  <active-response>
    <command>rpm_lookup</command>
    <rules_group>syscheck,,</rules_group>
    <level>5</level>
    <location>local</location>
  </active-response>

  <active-response>
    <command>ip_all</command>
    <level>4</level>
    <location>server</location>
  </active-response>

  <active-response>
    <command>rule_all</command>
    <level>4</level>
    <location>server</location>
  </active-response>
```

3. Add decoder for log files generated from AR scripts. Place in `$OSSEC/etc/local_decoder.xml`
```
<!--
      - rpm_lookup decoder
 - Will extract the status and filename (as id)
 - Examples:
 - 2016-01-26T13:18:55.940806-06:00 ossec-sec rpm_lookup.sh: OK: /usr/bin/floppy (Regular file) RPM verification passed
 -->
<decoder name="rpm_lookup">
  <program_name>^rpm_lookup.sh$</program_name>
</decoder>

<decoder name="rpm_lookup_info">
  <parent>rpm_lookup</parent>
  <regex>^(\S+): (\S+)</regex>
  <order>status, id</order>
</decoder>

<!--
      - puppetdb_lookup decoder
 - Will extract the status and filename (as id)
 - Examples:
 - 2016-01-26T13:33:20.774122-06:00 ossec-sec puppetdb_lookup.sh: WARNING: File /usr/bin/javac not found for polob.ncsa.illinois.edu
 -->
<decoder name="puppetdb_lookup">
  <program_name>^puppetdb_lookup.sh$</program_name>
</decoder>

<decoder name="puppetdb_lookup_info">
  <parent>puppetdb_lookup</parent>
  <regex>^(\S+): File (\S+)</regex>
  <order>status, id</order>
</decoder>
```

4. Add rules for AR scripts 

```
  <rule id="120001" level="14">
    <program_name>virustotal_lookup.sh</program_name>
    <match>Malicious hash found</match>
    <description>Malware hash found in Virus Total</description>
  </rule>

  <rule id="120002" level="14">
    <program_name>cymru_lookup.sh</program_name>
    <match>WARNING</match>
    <description>Malware hash found in Team Cymru Malware Hash Registry</description>
  </rule>

   <rule id="120003" level="0">
     <decoded_as>rpm_lookup</decoded_as>
     <description>Custom RPM Lookup Alert</description>
     <group>rpm_lookup</group>
   </rule>

   <rule id="120004" level="11">
     <if_sid>120003</if_sid>
     <program_name>rpm_lookup.sh</program_name>
     <match>WARNING</match>
     <description>File has been modified, entry in RPM database differs</description>
     <group>rpm_lookup</group>
   </rule>

   <rule id="120005" level="0">
     <decoded_as>puppetdb_lookup</decoded_as>
     <description>Custom PuppetDB Lookup Alert</description>
     <group>puppetdb_lookup</group>
   </rule>

   <rule id="120006" level="11">
     <if_sid>120005</if_sid>
     <program_name>puppetdb_lookup.sh</program_name>
     <match>WARNING</match>
     <description>Modified file not managed by Puppet</description>
     <options>no_email_alert</options>
     <group>puppetdb_lookup</group>
   </rule>

  <rule id="120007" level="12" timeframe="10">
    <if_matched_sid>120006</if_matched_sid>
    <if_sid>120004</if_sid>
    <same_id />
    <description>File has been modified and is not in PuppetDB or RPM database</description>
  </rule>
```
