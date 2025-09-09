# SOC-automation

## Objective
The goal of this project is to build a Hands-on Security Operations Center (SOC) lab that simulates a real-world detection, analysis and response workflow. The lab focuses on:

- Endpoint Visibility through detailed telemetry collection and monitoring.
- Centralized log management and search to enable efficient threat hunting and incident detection.
- Intrusion Detection and monitoring across systems and networks.
- Automated case management and investigation to streamline incident handeling.
- Orchestration and automated response workflows to reduce manual efforts and improve SOC efficiency.

This environment provides a foundation for hands-on learning, threat detection experiments, and security automation, making it suitable for both research and demonstration of SOC capabilities. 

## Skills Learned
- Log collection and normalization.
- Threat detection and intrusion monitoring.
- Endpoint telemetry analysis
- Security Automation and orchestration
- Incident management
- Threat hunting and querying
- SOC workflow design

## Tools used
- Vultr: cloud hosting platform used for deploying and managing the virtual machines that power the lab.
- Wazuh: Log collection, intrusion detection and security monitoring.
- Elasticsearch: search and analytics engine for indexing, querying and visualizing security data.
- Sysmon: endpoint telemetry provider for detailed process, file and network activity monitoring on Windows.
- TheHive: case management and incident response platform for tracking and investigation security events.
- Shuffle: security automation and orchestration (SOAR) platform for building workflows that connect detections with response actions.


> [!NOTE]
> - TheHive on-prem installation, that has been used, only offers 16 days trial so be sure to finish the lab before that.
> - Vultr offers 250$ free credit to new users and requires a valid credit card. The 250$ will expire in one month so manage your time accordingly.
> - All of the above tools can be deployed on your local system too but require a lot of resources. For example, Wazuh will not install unless atleast 4 vCPUs are assigned to it.
> - We are using SSH so you can copy and paste commands, URLs and credentials. Clipboard requires a GUI to work.

## Procedure
1. Windows installation with Sysmon configuration
2. Ubuntu server installation on Vultr
3. Wazuh installation
4. TheHive installation
5. Shuffle installation
6. Tools Configuration
7. Malware Analysis (Mimikatz)

## Step 1: Windows installation with Sysmon configuration
- Windows will be installed locally as a VM as we will be running some malicious programs and it will help with containment.
- Please refer to the link for [VMWare download](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion) and [VmWare Installation](https://www.youtube.com/watch?v=LWfaeLEhsXA) , if you don't have a hypervisor installed.
- Windows installation can be found on [this link](https://github.com/satyu-a/SOC-Detection-Lab?tab=readme-ov-file#step-3-installing-windows-10-target-machine).
- Sysmon Configuration can be found [here](https://github.com/satyu-a/SOC-Detection-Lab?tab=readme-ov-file#part-2-sysmon-configuration-for-windows-10-pro). This repo also includes the configuration file for sysmon.

## Step 2: Ubuntu server installation on Vultr
1. Go to [Vultr's Website](https://www.vultr.com/promo/try250?service=try250&utm_source=google-apac-brand&utm_medium=paidmedia&obility_id=120041731416&&utm_campaign=APAC_-_India_-_Search_-_Vultr_Branded_-_1009&utm_term=vultr&utm_content=576764022467&gad_source=1&gad_campaignid=12581233841&gbraid=0AAAAADMuDjDKeix8-eCOhfP5h1JuIW9LI&gclid=CjwKCAjw_fnFBhB0EiwAH_MfZt4nG8hxnGOFbXzSaCqnpb8mHFpnXShWA0dWCMN4RcHoWBV6pehrYRoCxzoQAvD_BwE) and signup for an account. Free credit will be available under **"Billing"**.

2. Dashboard should look like this:
   <img width="1678" height="907" alt="image" src="https://github.com/user-attachments/assets/aec0dc2d-a85c-4b24-8fea-ed99eae28c04" />

3. Click on **"Deploy New Server"**
   <img width="1622" height="902" alt="image" src="https://github.com/user-attachments/assets/3ab18aa0-b720-4b5f-9697-941a6a80a11f" />

4. Scroll down and selects these settings: The config we need is 4 vCPU, 8GB ram and 75 GB storage. This meets the min requirement of Wazuh. Then click **"Configure Software"**.
   <img width="1759" height="910" alt="image" src="https://github.com/user-attachments/assets/edab6583-319d-4090-809a-e04c573b6c61" />

5. Select **"Ubuntu"** as the OS with version 22.04 , Scroll down further and set **"Hostname"** to wazuh. Then Click **"Deploy"**
   <img width="1756" height="911" alt="image" src="https://github.com/user-attachments/assets/3f0d7b15-3257-45f2-b669-4f2fa48524bd" />

6. While the server is deploying, we need to create firewall rules so we can access the server from our local machine. Navigate like this: **Products > Network > Firewall**. Now we need to add firewall.
   <img width="1711" height="902" alt="image" src="https://github.com/user-attachments/assets/29047b8b-aab4-4395-9b6b-a89309edcfbc" />

7. In the IPv4 rule add a rule to allow us access to all ports, i.e, 65535 ports. You can find your IP address from [whatismyipaddress](https://whatismyipaddress.com/). Set a discription, for example: wazuh-firewall. Use these settings and click **+** to add the rule. Add for both TCP and UDP.
   <img width="1686" height="860" alt="image" src="https://github.com/user-attachments/assets/c53be040-71e1-4909-8e00-4e834002567e" />

8. Now go to **Compute** and the server should be there. Select **Server Details**.
   <img width="1616" height="821" alt="image" src="https://github.com/user-attachments/assets/362b9e08-092c-4a1e-aa0b-c9ea10c18ca0" />

9. Go to **"Settings > Firewall"** and select the firewall rule we created and update the firewall group.
   <img width="1725" height="845" alt="image" src="https://github.com/user-attachments/assets/e9b26e67-9c1c-4874-b4dd-3197c61c7723" />

10. Go to your server overview and your should see the credentials to access the server. We will be using these to login via SSH protocol,
    <img width="1827" height="886" alt="image" src="https://github.com/user-attachments/assets/ea991f82-7a01-43ab-b33c-fc2f9ca6a7f9" />

10. Now that the server is ready, lets access it from our desktop. Open command Prompt with administrator privillages and connect to the server via SSH. It might ask to create a "Fingerprint" type Yes and then enter the password:

        ssh root@<Your_Server_IP_address>
      
11. If the login was successful, your username will change to "root". Now as a root user we no longer need to use Sudo command. Run the update command:

        apt-get update && apt-get upgrade -y

12. Now check if any firewall is active on the ubuntu:

        ufw status
    <img width="1062" height="306" alt="image" src="https://github.com/user-attachments/assets/15572316-1e9a-439e-823c-56e12e56f5e3" />

13. If its active, we need to either add a rule to allow certain ports or disable it. Otherwise we won't be able to access the Wazuh dashboard from our web browser. Since this is a lab environment, I will be disabling it.

        ufw disable
    <img width="1085" height="146" alt="image" src="https://github.com/user-attachments/assets/621598a3-061e-4279-9091-81def2db4c25" />

- One server is ready. Now as a challange, deploy two additional servers withe the following configs and repeat till step **13**
- Hostname: TheHive, 2 vCPU, 8GB ram, any storage is fine and the location should be same as Wazuh. Create same firewall rules under **"thehive"** name.
- Hostname: Shuffle, 2 vCPU, 8GB ram, any storage is fine and the location should be same as Wazuh and TheHive. Create same firewall rules under **"shuffle"** name.


## Step 3: Wazuh installation

1. Connect to the wazuh server using SSH and the root credentials from Vultr and run the command. You can also find the installation steps in [Wazuh Official Document](https://documentation.wazuh.com/current/quickstart.html).

       curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
    <img width="1082" height="223" alt="image" src="https://github.com/user-attachments/assets/aad3848a-63e5-44cb-8b2b-c7083b7cf938" />

2. After installation is finished, it will generate Default credentials for you, store them somewhere also right above the credentials, access URL is generated to access wazuh dashboard:
     <img width="1082" height="646" alt="image" src="https://github.com/user-attachments/assets/5ec37bb4-be66-457b-a6cc-308eca65655c" />

3. Check the wazuh status after installation to be double sure:

       systemctl status wazuh-manager
     <img width="1099" height="549" alt="image" src="https://github.com/user-attachments/assets/b631b7ec-9ad6-4a40-a188-e67f91f3c3e0" />

4. Open the URL in your web browser. Use the server IP as the domain name. It may show a warning, just ignore proceed as usual:
     <img width="1908" height="938" alt="image" src="https://github.com/user-attachments/assets/be3ca407-1ac3-4ff6-8cec-2a4cbd1f0a68" />

5. Enter the credentials generated by wazuh-manager and you should be greeted by the admin dashboard:
     <img width="1908" height="958" alt="image" src="https://github.com/user-attachments/assets/6d4970cb-f9ba-4e9e-9013-50cad911d085" />


## Step 4: TheHive installation  

1. Connect to the wazuh server using SSH and the root credentials from Vultr.
     <img width="1079" height="604" alt="image" src="https://github.com/user-attachments/assets/30d93458-8869-4072-a171-22bded1eb563" />

2. Now we need to install some Prerequisites. You can refer to this document [TheHive Installation](https://docs.strangebee.com/thehive/installation/step-by-step-installation-guide/).<br>
   In total we will be installing four components after the installation of the prerequisites: JAVA 11, Elasticsearch, Cassandra and TheHive itself.

     1. Prerequisites:

            apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release

     2. JAVA 11: Check java version after installation is complete. In case it does not show, run eeach command individually.
  
            wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
            echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
            sudo apt update
            sudo apt install java-common java-11-amazon-corretto-jdk
            echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
            export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"

      - Check java version:

            java --version
           
      3. Cassandra:
          - Download Apache Cassandra repository keys using the following command:

                wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg

          - Add the repository to your system by appending the following line to the /etc/apt/sources.list.d/cassandra.sources.list file. This file may not exist, and you may need to create it:

                echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 41x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list

          - Once the repository references are added, update your package index:

                sudo apt update
          
          - Install Cassandra:

                sudo apt install cassandra
                
      4. Elasticsearch:
          - To add Elasticsearch repository keys, execute the following command:

                wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
                sudo apt-get install apt-transport-https
          - Add the repository to your system by appending the following line to the /etc/apt/sources.list.d/elastic-7.x.list file. This file may not exist, and you may need to create it:

                 echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list

          - Update your package index:

                  sudo apt update

          - Install elsaticsearch:
       
                  sudo apt install elasticsearch

      5. TheHive:
           - Download the installation package:

                  wget -O /tmp/thehive_5.5.8-1_all.deb https://thehive.download.strangebee.com/5.5/deb/thehive_5.5.8-1_all.deb
                  wget -O /tmp/thehive_5.5.8-1_all.deb.sha256 https://thehive.download.strangebee.com/5.5/sha256/thehive_5.5.8-1_all.deb.sha256
                  wget -O /tmp/thehive_5.5.8-1_all.deb.asc https://thehive.download.strangebee.com/5.5/asc/thehive_5.5.8-1_all.deb.asc
                   
           - Install TheHive:

                   sudo apt-get install /tmp/thehive_5.5.8-1_all.deb


## Shuffle Installation
We can either use shuffle via logging onto the shuffle website or we can self-host it on the cloud. For this lab, we will be hosting a shuffle instance on Vultr.
Shuffle require two components to be installed first:
- Docker
- Docker Compose






## Tools Configuration

1. Cassandra:
      
      1. Locate the Cassandra configuration file and open it in a text editor using command:

               nano /etc/cassandra/cassandra.yaml
         <img width="1082" height="636" alt="image" src="https://github.com/user-attachments/assets/1c1cceee-030b-4308-a550-ed073b6df290" />

      2. Configure the following, replace with your config elements and save the file with "ctrl + X" then "Y" and then "Enter":
           - cluster_name: 'your_cluster_name'
           - listen_address: ip_address_of_thehive_server
           - rpc_address: ip_address_of_thehive_server
           - seeds: "ip_address_of_thehive_server:9000"

      3. Stop cassandra and start it. This will allow the new config to be loaded on the memory:

             systemctl stop cassandra.service

      4. Delete Old files:

             sudo rm -rf /var/lib/cassandra/*
      
      5. Start Cassandra.service and enable it on startup:

             systemctl start cassandra.service
             systemctl enable cassandra.service

      6. Check status, if its active, all good:

             systemctl status cassandra
 
 2. Elasticsearch:
      1. Locate the Cassandra configuration file and open it in a text editor using command:

             nano /etc/elasticsearch/elasticsearch.yml
         <img width="1081" height="606" alt="image" src="https://github.com/user-attachments/assets/bd8ae17a-4dbe-4ed9-9f42-1c345670010b" />               

      2. Configure the following, uncomment and replace with your config elements and save the file with "ctrl + X" then "Y" and then "Enter":
          - cluster.name: thehive
          - node.name: node-1
          - network.host: Ip_address_of_thehive_server
          - http.port: 9200
          - cluster.initial_master_nodes: ["node-1"] (We removed node-2 because in lab environment we don't need to scale the ES, one node would be enough)
        
      3. Stop elasticsearch and start it. This will allow the new config to be loaded on the memory:

             systemctl stop elasticsearch
           
      4. Start elasticsearch.service and enable it on startup:

             systemctl start elasticsearch.service
             systemctl enable elasticsearch.service

      5. Check status, if its active, all good:

             systemctl status elasticsearch

  3. TheHive:
      1. Check the permissions of TheHive directory: "/opt/thp/thehive/files." and make sure thehive user has access to it, if not change permissions:
         - Check permissions:

                   ls -la /opt/thp/
             <img width="1078" height="169" alt="image" src="https://github.com/user-attachments/assets/3f2da304-db84-4990-b10c-0a6a340881b8" />
         - Change permission to thehive user

                   chown -R thehive:thehive /opt/thp
             <img width="1082" height="189" alt="image" src="https://github.com/user-attachments/assets/a3130fd8-a94a-48e1-8eaa-ae0ed989f120" />

       2. Open TheHive configuration file:

              nano /etc/thehive/application.conf

       3. Change the configuration values to the following and replace with your config elements and save the file with "ctrl + X" then "Y" and then "Enter":
          - hostname = ["ip_address_of_thehive_server"] (for both cassandra and elasticsearch)
          - cluster_name: Your_cluster_name (the one entered in cassandra config)
          - application.baseUrl: "http://IP_address_of_thehive_server:9000"

       4. Stop thehive and start it. This will allow the new config to be loaded on the memory:

              systemctl stop thehive
           
       5. Start elasticsearch.service and enable it on startup:

              systemctl start thehive.service
              systemctl enable thehive.service

       6. Check status, if its active, all good:

              systemctl status thehive

> [!NOTE]
> If you are unable to access TheHive dashboard, check status of elasticsearch, thehive and cassandra.
> Default Cred are: username:admin, password:secret

4. Wazuh:
      1. Your Wazuh credentials are stored in passwords.txt. To access this file:
            - Check if these folders are available in your home directory
                 <img width="1058" height="202" alt="image" src="https://github.com/user-attachments/assets/d98f9fb4-212f-4306-8071-43ae4a889d6c" />
            - Extract the .tar file, the highlighted file has all your default credentials:

                    tar -xvf wazuh-install-files.tar
                 <img width="1090" height="587" alt="image" src="https://github.com/user-attachments/assets/5bffc4c6-bddf-4c17-b3e8-d28031f51f80" />

      2. On the windows virtual machine, open wazuh dashboard and click on **"Deploy new Agent"**:
            <img width="1912" height="894" alt="image" src="https://github.com/user-attachments/assets/e7bab749-783f-4b42-9de9-288b6279ab49" />

      3. Select Windows, Enter the wazuh server IP address and assign an agent name:
            <img width="1831" height="731" alt="image" src="https://github.com/user-attachments/assets/0572a26a-98ad-46fb-8de7-53bc4c69d156" />

      4. Scroll down and copy the generated command in Powershell as Administrator:
            <img width="1803" height="554" alt="image" src="https://github.com/user-attachments/assets/b7a07ed9-f183-480b-9358-64dc4d72c473" />

      5. Start the service using the command:

               NET START WazuhSvc

      6. Go to the **"Overview"** tab in Wazuh dashboard and you should be able to see the Agent. It might take some time and you might have to refresh the dashboard a few times. Click on active and then click on the windows agent that we added.
            <img width="1894" height="758" alt="image" src="https://github.com/user-attachments/assets/f0440798-1bab-414d-84ce-e7aee389f334" />
            <img width="1903" height="794" alt="image" src="https://github.com/user-attachments/assets/75dbcf2e-5721-4018-8655-d33098324d25" />

      7. By default Wazuh only logs something if a rule or alert is triggered. So we need to edit the config of wazuh-manager to log everything. Connect to the wazuh server via ssh and open
      the **"ossec.conf"** file stored in the directory: **"/var/ossec/etc/ossec.conf"**. Make a copy of the config file and store it in home incase we break something:

               cp /var/ossec/etc/ossec.conf ~/ossec-bkp.conf
      8. Now open the config file in a file editor:
   
               nano /var/ossec/etc/ossec.conf
      9. Now change the following fields to Yes. This would allow all logs to be stored in the archives and displayed on the dashboard. **"Ctrl + X" then "Y" then "Enter"** to save the file
            <img width="1106" height="636" alt="image" src="https://github.com/user-attachments/assets/c9682726-70d8-4b21-bbe3-187f279db81a" />
   
      10. Restart the wazuh-manager:
   
               systemctl restart wazuh-manager
   
      11. All logs will be store in the archives file in the directory **"/var/ossec/logs/archives"**. Switch to the directory and check if the file is there
   
               ls /var/ossec/logs/archives
            <img width="1063" height="89" alt="image" src="https://github.com/user-attachments/assets/b449046a-044f-4b08-9d94-9eb885d3165f" />
   
      12. Now for Wazuh to ingest the archives logs, we need to make changes in the filesbeats config file:
   
               nano /etc/filebeat/filebeat.yml
   
      13. In the config, set **"enabled: true"** under **"archives"** and **"Ctrl + X" then "Y" then "Enter"** to save the file.
   
            <img width="1094" height="635" alt="image" src="https://github.com/user-attachments/assets/96d86635-889f-4dba-8357-e434e8d2be2c" />
   
      14. Restart filebeat service
   
              systemctl restart filebeat
   
      15. Now to create an **"archives"** index pattern on our wazuh dashboard so we can see the archived logs go to **"Dashboard management"**:
   
             <img width="1643" height="758" alt="image" src="https://github.com/user-attachments/assets/0274e9f8-97cd-45df-9b91-7fc507e8d6e4" />
   
      16. Click **"Index Patterns"** then **"Create Index pattern"**
   
             <img width="1906" height="637" alt="image" src="https://github.com/user-attachments/assets/10d6b6dd-7daf-4faa-ab8c-b7f6069d4f48" />
   
      17. Create a new pattern named **"wazuh-archives-*"** and click **"Next Step"**
   
             <img width="1788" height="718" alt="image" src="https://github.com/user-attachments/assets/79815aa7-63ca-4a7e-9063-a5476df35f91" />
   
      18. Select **"timestamp"** from the bottom and click **"Create Index Pattern"**
   
             <img width="1794" height="703" alt="image" src="https://github.com/user-attachments/assets/887bab8b-beae-43b0-a891-116fdbfa67cc" />
   
      19. Head over to Discover:
   
             <img width="1805" height="779" alt="image" src="https://github.com/user-attachments/assets/4932f463-a709-440a-9b4e-d1bdde3dbfe1" />
   
      20. From the dropdown menu select the index pattern we created and the click **"Refresh"** to see the new logs. it might take some time:
   
             <img width="1850" height="739" alt="image" src="https://github.com/user-attachments/assets/041da8f4-bdaf-4250-a7e5-7228028c1aae" />


> [!NOTE]
> If the wazuh-agent installation fails, then uninstall and delete any wazuh-agent files using the control pannael before reinstallion attempt.

5. Windows telemetry:
      - Configure wazuh to ingest Sysmon logs:
           1. All wazuh files are located under **C:\Program Files (x86)\ossec-agent** directory. Here you will find a **"ossec.conf"** file. Make a copy of the file and rename it to
              **"ossec-backup.conf"** so incase of any misconfiguration, we can revert to original config.
                 <img width="1129" height="594" alt="image" src="https://github.com/user-attachments/assets/6e6eb321-ddb0-425a-8c27-e782dfd94fc5" />

           3. Open Notepad with administrator privilages and then open the **"ossec.conf"** file in the notpad from the above directory. If unable to see file, change the extension to
              **"All files"**
                 <img width="1275" height="609" alt="image" src="https://github.com/user-attachments/assets/e8bf3b97-333e-4838-9020-24082384795f" />
           
           4. Scroll down to the **"Log Analysis"** and paste the following snippet. This will enable the wazuh agent to ingest Sysmon logs. Be careful of the indentation. Also remove
               Application, security and system logfile snippets as, for this lab, we want to fucus on Sysmon logs only:

                    <localfile>
                      <location>Microsoft-Windows-Sysmon/Operational</location>
                      <log_format>eventchannel</log_format>
                    </localfile>

           5. New file look something like this, save the file:
                 <img width="1274" height="604" alt="image" src="https://github.com/user-attachments/assets/2753330e-c243-489e-9b58-edf426f4849d" />

           6. Restart the Wazuh service from **"Services"**
                 <img width="1690" height="795" alt="image" src="https://github.com/user-attachments/assets/2518ee5a-99be-4001-88b5-739dfb35e47f" />

           7. On the Wazuh dashboard Click on **"Threat Hunting"**:
                 <img width="1853" height="715" alt="image" src="https://github.com/user-attachments/assets/90ab52b4-82b8-4403-963a-0046e9233b20" />

           8. Then Click on **"Events"** Tab and you should be able to see the logs. if you don't, type **"Sysmon"** in the search field and Click **"Refresh"**.
              Overall it may take some time for the logs to be available:
                 <img width="1903" height="794" alt="image" src="https://github.com/user-attachments/assets/ed5b720b-8013-4222-9a57-bd8cd4c4fcf6" />

## Malware Analysis

> [!CAUTION]
> This Section is purely for learning and demonstration of SOC capabilities. DO NOT use this to cause harm cuz both god and cops are watching and you don't want to be on their naughty list!!
   - Mimikatz is a tool used for credential dumping,i.e, to steal credentials lis passwords, hashes, etc. And is detectable by antiviruses. So before downloading it, either disable the anti-virus and firewalls on the Windows VM or add an exclusion rule in the anti-virus to exclude the downloads folder from scanning. Always enable the security after the lab is completed. 
 
   1. Download Mimikatz from the github link: Its safe to download btw :) [Mimikatz Github Link](https://github.com/ParrotSec/mimikatz) and select **Download zip**
         <img width="1851" height="693" alt="image" src="https://github.com/user-attachments/assets/89aa21f0-314b-4285-bfdf-6e4e5e595156" />

   2. Extract the contents of the file. It will be stored in Mimikatz-master folder:
         <img width="1108" height="414" alt="image" src="https://github.com/user-attachments/assets/d2f526a2-a721-4fdb-9f36-a31063f4df9f" />

   3. A troubleshooting step: To see if there are certain logs in archives , enter the following command in this case I'll be looking for mimikatz:

            cd /var/ossec/logs/archives
            cat archives.json | grep -i mimikatz

   4. No output means no logs:
         <img width="1083" height="89" alt="image" src="https://github.com/user-attachments/assets/85726a0a-5d14-4baf-bc90-08e5140cf662" />

   5. Now time to execute mimikatz and generate some events. Open Powershell and head to mimikatz directory:
         <img width="1521" height="396" alt="image" src="https://github.com/user-attachments/assets/a7a683ff-364f-4bb0-aff2-223042cc30b8" />

   6. in this case, mimikatz executable is located in **"Win32"** folder so go to that folder and execute mimikatz:
         <img width="962" height="401" alt="image" src="https://github.com/user-attachments/assets/5d47817e-a360-4d0b-bcd9-36b6f187f9f8" />

   7. If it shows warning like this, click **"Run anyway"**:
      
         <img width="534" height="504" alt="image" src="https://github.com/user-attachments/assets/c5469bbb-d80c-469f-bd36-d58f2322d9fe" />

   9. Now if we go back to the wazuh-manager CLI, and check the archives log, we should see mimikatz there:
         <img width="1090" height="516" alt="image" src="https://github.com/user-attachments/assets/d6c85ee3-7eda-4745-90c2-a558e29e5194" />

   10. On the wazuh dashboard, search for mimikatz and events should be there:
         <img width="1855" height="746" alt="image" src="https://github.com/user-attachments/assets/bd994847-8a15-4cfc-a214-0958a31f949d" />

   11. Now we need to fetch the event with **"data.win.system.eventID = 1"** which is the id for process creation event. To do that, we can set a filter that will show us only these events:
          <img width="1454" height="678" alt="image" src="https://github.com/user-attachments/assets/e9d5db3e-77b0-4aea-8c1a-8bcf7d6f48c0" />

   12. Now there is only one event with ID = 1 in my case. Expand that event to see more information:
          <img width="1476" height="701" alt="image" src="https://github.com/user-attachments/assets/f945d3b1-bb94-4493-9d20-5cad5ee6d667" />

   13. Now we will xreate an alert for mimikatz. To do the we will use the field **"originalFileName"**. We can use other fields but this field will trigger the alert even if the attacker
       renames the file to mimicow (lol). 
          <img width="1464" height="688" alt="image" src="https://github.com/user-attachments/assets/8a28f77b-8283-43e9-9be1-46fd7904be63" />

   14. To create an alert, we need to add a rule to the wazuh config, which we can acccess via the dashboard (Thank wazuh-god) so head to **"Custom rules"** file:
          <img width="1837" height="751" alt="image" src="https://github.com/user-attachments/assets/505b7a95-8ea0-49b3-b6b5-314812a48755" />
          <img width="1846" height="657" alt="image" src="https://github.com/user-attachments/assets/f4205a16-c167-4c5d-9bb7-f1753c7a3ecc" />
          <img width="1837" height="596" alt="image" src="https://github.com/user-attachments/assets/189b044b-afeb-432a-9fb4-95e0e7c87f2c" />
          <img width="1838" height="372" alt="image" src="https://github.com/user-attachments/assets/41a06fd5-4405-4f94-a87e-ffd096d6e0fc" />

   15. Add a rule to detect mimikatz:
          - Custom rules always start from ID = 100000.
          - Levels 1-15: 1 is lowest in severity and 15 is the highest.
          - Mitre ID: t1003: Credential Dumping (What mimikatz is known for)
          - type="pcre2": Regex
          - And be careful about the indentation and case sensitivity and save it:
          - Restart the manager as prompted
         
                <rule id="100002" level="15">
                   <if_group>sysmon_event1</if_group>
                   <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>   
                   <description>Mimikatz Activity Detected</description>
                   <mitre>
                       <id>T1003</id>
                   </mitre>
                 </rule>

          <img width="878" height="638" alt="image" src="https://github.com/user-attachments/assets/bdc767ac-478f-4c77-895a-160005de890b" />

   16. To prove the field usage point, lets change the file name of mimikatz to "trustmebro" and see if the alert catches it:
          <img width="660" height="218" alt="image" src="https://github.com/user-attachments/assets/5da0d754-513b-4dfa-af78-a727916bbdd1" />

   17. Run mimikatz again from the powershell:
          <img width="892" height="203" alt="image" src="https://github.com/user-attachments/assets/9d559aee-b203-4643-9dd3-5222c19b5364" />

   18. Heading back to dashboard, an alert should be triggered:
          <img width="1829" height="728" alt="image" src="https://github.com/user-attachments/assets/8d76a4b9-70e5-4082-94ef-3b9f2670ba54" />

   19. Go to Events, the alert information should be there as expected. Also additional fileds can be added to the table. Expand the alert:
          <img width="1868" height="722" alt="image" src="https://github.com/user-attachments/assets/5fddd600-1ff6-4211-bb8c-563f7ffc94e9" />

   20. Inspecting the document, we can see that the image is changed but the original filename still detects mimikatz:
          <img width="1868" height="756" alt="image" src="https://github.com/user-attachments/assets/72cc3bab-d27b-425b-82cf-9a70ba541db6" />

Pat yorself on the back for catching evil!! Now all we need to do is to automate our project:
- The file needs to be enriched to confirm its malacious
- SOC analyst should be alerted via Email if an alert is triggered
- And all of this should be done seemlessly, i.e, with the help of SOAR.





















 














            
      
            

            
