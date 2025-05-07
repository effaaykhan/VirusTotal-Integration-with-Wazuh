# VirusTotal-Integration-with-Wazuh
- This Repo contains the step by step guide for detecting and removing malware using wazuh. 
- Wazuh employs the integrator module to establish a connection with external APIs and alerting systems, such as VirusTotal.

- In this scenario, the Wazuh File Integrity Monitoring (FIM) module is utilized to monitor a specific directory for any modifications, while the VirusTotal API is employed to scan the files within said directory. Subsequently, Wazuh is configured to initiate an active response script that promptly eliminates any files identified as malicious by VirusTotal. This use case has been tested on both Ubuntu and Windows endpoints.

To authenticate Wazuh with the VirusTotal API in this particular use case, it is essential to possess a valid VirusTotal API key.

## Configuring the Windows endpoint
- Perform the following steps to set up Wazuh for monitoring near real-time modifications in the ```/Downloads``` folder. These steps include installing the required packages and creating an active response script to delete potentially harmful files.

1. Search for the ```<syscheck>``` block in the Wazuh agent ```C:\Program Files (x86)\ossec-agent\ossec.conf``` file. Make sure that ```<disabled>``` is set to ```no```. This enables the Wazuh FIM module to monitor for directory changes.
2.  Include an entry in the ```<syscheck>``` block to set up monitoring for a specific directory in almost real-time. In this scenario, I will configure Wazuh to monitor the ```C:\Users\<USER_NAME>\Downloads``` folder. Replace ```<USER_NAME>``` with the relevant user name.
```
<directories realtime="yes">C:\Users\<USER_NAME>\Downloads</directories>
```
3. Download the Python executable installer from the [official Python website](https://www.python.org/downloads/windows/).
4.  Execute the Python installer after it has been downloaded. Select the appropriate options:
   - Install launcher for all users
   - Add Python 3.X to PATH (This places the interpreter in the execution path)
5. After Python finishes the installation, open an administrator PowerShell terminal and proceed with installing PyInstaller using pip.
```
pip install pyinstaller 
pyinstaller --version
```
   - Pyinstaller is utilized in this case to convert the Python script responsible for generating active responses into a standalone executable application compatible with Windows endpoints.
6. Create an active response script remove-threat.py to remove a file from the Windows endpoint:
```
notepad remove-threat.py
```
   - [remove-threat.py](https://github.com/effaaykhan/VirusTotal-Integration-with-Wazuh/blob/main/remove-threat.py)

7. Transforming the Python script remove-threat.py into a Windows executable application can be achieved by executing the following PowerShell command as an administrator:
```
pyinstaller -F \path_to_remove-threat.py
```
   - Take note of the path where pyinstaller created remove-threat.exe. (You will find it mostly in dist directory which can be found in the current directory).
8. Move the executable file ```remove-threat.exe``` to the ```C:\Program Files (x86)\ossec-agent\active-response\bin directory```.

9. Restart the Wazuh agent to apply the changes.
```
Restart-Service WazuhSvc
```

## Configuring the Wazuh server
- To configure the integration between Wazuh and VirusTotal, follow these steps on the Wazuh server. These steps will also activate and trigger the active response script when a suspicious file is found.

1. Insert the provided configuration into the ```/var/ossec/etc/ossec.conf``` file on the Wazuh server. This configuration enables the integration with VirusTotal, allowing VirusTotal queries to be triggered whenever any of the rules in the FIM syscheck group are activated.
```
   <integration>
    <name>virustotal</name>
    <api_key><YOUR_VIRUS_TOTAL_API_KEY></api_key> <!-- Replace with your VirusTotal API key -->
    <group>syscheck</group>
    <alert_format>json</alert_format>
  </integration>
```
  
  - Replace <YOUR_VIRUS_TOTAL_API_KEY> with you own virustotal api key.
  - Note: The free VirusTotal API rate limits requests to four per minute. With a premium VirusTotal API key, high frequency of queries are allowed, and more rules can be added besides these two. Wazuh can also be be configured to monitor more directories besides ```C:\Users\<USER_NAME>\Downloads```.

2. Append the following blocks to the Wazuh server ```/var/ossec/etc/ossec.conf``` file. This enables active response and trigger the remove-threat.exe executable when the VirusTotal query returns positive matches for threats:
```
  <command>
    <name>remove-threat</name>
    <executable>remove-threat.exe</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>remove-threat</command>
    <location>local</location>
    <rules_id>87105</rules_id>
  </active-response>
```
3. Add the following rules to the Wazuh server ```/var/ossec/etc/rules/local_rules.xml``` file to alert about the active response results.
```
<group name="virustotal,">
  <rule id="100092" level="12">
      <if_sid>657</if_sid>
      <match>Successfully removed threat</match>
      <description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>

  <rule id="100093" level="12">
    <if_sid>657</if_sid>
    <match>Error removing threat</match>
    <description>Error removing threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
</group>
```
  - Same rule ID was used during the testing of this capability on the Ubuntu machine.
4. Restart the Wazuh manager to apply the configuration changes.
```
systemctl restart wazuh-manager
```

## Attack emulation
1.  Download an [EICAR test file](https://secure.eicar.org/eicar.com.txt) to the ```C:\Users\<USER_NAME>\Downloads``` directory on the Windows endpoint.
```
Invoke-WebRequest -Uri https://secure.eicar.org/eicar.com.txt -OutFile eicar.txt 
cp .\eicar.txt C:\Users\<USER_NAME>\Downloads
```
  - This triggers a VirusTotal query and generates an alert. In addition, the active response script automatically removes the file.

## Visualization
- The alert data are visualized in the Wazuh dashboard. Go to the Security events module and add the filters in the search bar to query the alerts.

Filter the events- 
```
rule.id: (554 OR 100092 OR 553 OR 87105)
```
- It can be seen that once the file was downloaded, VirusTotal detected the file as malicious and the active-response automatically deletes the file.

![image](https://github.com/user-attachments/assets/70b7e4e5-726f-4b46-8550-40eaf5cbcf1e)

                      ### End of Virustotal Integration###

                      

# CDB lists and threat intelligence
- Wazuh helps detect harmful files by comparing them to a list of known bad files. This list, called a CDB list, includes indicators like file names, IP addresses, and domain names. New entries can be added to the CDB list and use it to either allow or prevent access to certain files. To learn more, check out the [CDB list documentation](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html)

## How it works
- Wazuh checks if field values, such as IP address, file hashes, and others, extracted from security events during decoding are in a CDB list to hunt and detect malware. To detect malware, a CDB lists with the file integrity monitoring (FIM) module is employed. Below describes how it works:
  - The Wazuh FIM module scans monitored directories on endpoints to identify alterations like file creation and modifications. The FIM module stores the checksums and attributes of the monitored files.
  - When the FIM module generates an alert, the Wazuh analysis engine compares the file attributes, such as the file hash, to the keys in a predefined CDB list.
  - If the Wazuh analysis engine discovers a match, it generates or suppresses an alert based on how the rule is configured.

## Use case: Detecting malware using file hashes in a CDB list
- Note: In the Wazuh documentation, this use case was tested on an Linux endpoint.

- In this use case, I will test how to detect malware using file hashes that have been added to a CDB list.

## Configuring the Wazuh server
1. Create a CDB list malware-hashes of known malware hashes and save it to the /var/ossec/etc/lists directory on the Wazuh server.
```
nano /var/ossec/etc/lists/malware-hashes
```

2. Add the known malware hashes to the file as key:value pairs. In this case, I used the known MD5 hashes of the Mirai and Xbash malware as shown below.
```
e0ec2cd43f71c80d42cd7b0f17802c73:mirai 
55142f1d393c5ba7405239f232a6c059:Xbash

3. Add a reference to the CDB list in the Wazuh manager configuration file ```/var/ossec/etc/ossec.conf``` by specifying the path to the list within the ```<ruleset>``` block:
```
<ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <list>etc/lists/malware-hashes</list>
  <ruleset>
  ```
  4. Craft a custom rule in the ```/var/ossec/etc/rules/local_rules.xml``` document on the Wazuh server. This rule triggers events when Wazuh identifies a match between the MD5 hash of a recently modified or created file and a hash in the CDB list. Rule numbers 554 and 550 will match events that indicates the existence of a newly updated or created file.
  ```
  <group name="malware,">
  <rule id="110002" level="13">
    <!-- The if_sid tag references the built-in FIM rules -->
    <if_sid>554, 550</if_sid>
    <list field="md5" lookup="match_key">etc/lists/malware-hashes</list>
    <description>File with known malware hash detected: $(file)</description>
    <mitre>
      <id>T1204.002</id>
    </mitre>
  </rule>
    <rule id="110003" level="5">
    <if_sid>110002</if_sid>
    <field name="file" type="pcre2">(?i)[c-z]:</field>
    <description>A file - $(file) - in the malware blacklist was added to the system.</description>
  </rule>  
</group>
```
5. Restart the Wazuh manager to apply changes.
```
systemctl restart wazuh-manager
```

## Configuring the Windows endpoint

1. Configure directory monitoring by adding the <directories> block specifying the folders to be monitored in the agent configuration file or using the centralized configuration option.
```
  <syscheck>
    <disabled>no</disabled>
    <directories check_all="yes" realtime="yes" whodata="yes">/PATH/TO/MONITORED/DIRECTORY</directories>
  </syscheck>
```
Note: The check_all option ensures Wazuh checks all file attributes including the file size, permissions, owner, last modification date, inode, and the hash sums.

2. Restart the Wazuh agent to apply the changes.
```
Service-Restart WazuhSvc
```

## Testing the configuration
To test that everything works correctly, download the Mirai and Xbash malware samples to the directory the FIM module is monitoring.

Warning: These malicious files are dangerous, so use them for testing purposes only. Do not install them in production environments.

1. Download the malware samples. Replace /PATH/TO/MONITORED/DIRECTORY with the path of the monitored directory, C:\Users\<USERNAME>\Downloads
```
Invoke-WebRequest -Uri https://wazuh-demo.s3-us-west-1.amazonaws.com/mirai -OutFile C:\Users\<USERNAME>\Downloads/mirai

Invoke-WebRequest -Uri https://wazuh-demo.s3-us-west-1.amazonaws.com/xbash -OutFile C:\Users\<USERNAME>\Downloads/Xbash
```

## Visualizing the alerts
![image](https://github.com/user-attachments/assets/45f82f24-eea2-4f9d-8e97-59ab34dbaf5e)


![image](https://github.com/user-attachments/assets/42a688da-ffbe-4bee-af49-036c0e7741ed)



## Configuring Active Response
- In this case, a Python script on a Windows agent is executed to remove the malicious files that were downloaded.

- Note the following items in the active response script:
   - The active response script is created on the agent.
   - If the active response script is being run on Linux-based endpoints, the first line on the script must indicate the Python interpreter.

- Create [remove-malware.py](https://github.com/effaaykhan/VirusTotal-Integration-with-Wazuh/blob/main/remove-malware.py)
```
notepad remove-malware.py
```
- To run a Python script on any Windows computer, convert it into an executable file using pyinstaller.
```
pyinstaller -F remove-malware.py
```
- Copy the built executable to C:\Program Files (x86)\ossec-agent\active-response\bin
```
Move-Item -Path remove-malware.exe -Destination "C:\Program Files (x86)\ossec-agent\active-response\bin"
```

## Configuring the Wazuh Server
- Now that the active response executable has been placed in the bin folder on the agent, proceed to configure the manager to trigger an active response when the malware blacklist detection rule is triggered. In the manager configuration file, the following block is added in the ossec_config block:

```
<command>
   <name>remove-malware</name>
   <executable>remove-malware.exe</executable>
   <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
   <disabled>no</disabled>
   <command>remove-malware</command>
   <location>local</location>
   <rules_id>110003</rules_id>
</active-response>
```
### Creating rules for the active response log
- To create rules to alert when the active response file removal succeeded or failed, add the following rule to the ```/var/ossec/etc/rules/local_rules.xml``` file on the manager then restart it.
```
<rule id="110004" level="7">
    <if_sid>657</if_sid>
    <match>Successfully removed threat</match>
    <description>$(parameters.program): Successfully removed threat $(parameters.alert.syscheck.path) whose MD5 hash appears in a malware blacklist.</description>
  </rule>
  <rule id="110005" level="7">
    <if_sid>657</if_sid>
    <match>Error removing threat</match>
    <description>$(parameters.program): Error removing threat $(parameters.alert.syscheck.path) whose MD5 hash appears in a malware blacklist.</description>
</rule>
```

### Testing the configuration
- Perform same test by downloading the malware samples in the Downlaods directory.
```
 Invoke-WebRequest -Uri https://wazuh-demo.s3-us-west-1.amazonaws.com/xbash -OutFile C:\Users\<USERNAME>\Downloads/mirai
 Invoke-WebRequest -Uri https://wazuh-demo.s3-us-west-1.amazonaws.com/xbash -OutFile C:\Users\<USERNAME>\Downloads/xbash
```

### Visualizing the alerts
- Filter --
  ```
  rule.id: (100092 OR 110003)
![image](https://github.com/user-attachments/assets/796d3ac2-955d-40e0-922a-fd832373a4cc)
