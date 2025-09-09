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
5. Tools Configuration
6. Malware Analysis (Mimikatz)
7. Automation and enrichment

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
Pat yourself on the back for catching evil!! Now all we need to do is to automate our project:



## Automation and enrichment
 - Basically we will be creating a workflow and connect all of the components we installed before, with Shuffle (SOAR):
      1. Mimikatz alret sent to shuffle
      2. Shuffle receives mimikatz alerts and extracts the hash value SHA256
      3. Check reputation with VirusTotal
      4. Send details to TheHive to create alert
      5. Send Email to SOC Analyst to begin investigation

1. Create a Shuffle account using this link: [Shuffle register](https://shuffler.io/register)

   <img width="1920" height="865" alt="image" src="https://github.com/user-attachments/assets/b16ec122-1f89-4d5b-9840-51ffc2d853e8" />

2. Select any:

   <img width="1085" height="530" alt="image" src="https://github.com/user-attachments/assets/48b76a64-39f0-466f-b49e-090e2f2899e6" />

3. Expand the sidebar and select **"Workflow"** and **"Create a new Workflow"**:

   <img width="1913" height="961" alt="image" src="https://github.com/user-attachments/assets/628f9a17-94f6-47be-a8a5-1c54b887491f" />

4. Assign a name and select any usecase then **"Create from Scratch"**:

   <img width="1910" height="917" alt="image" src="https://github.com/user-attachments/assets/d664c69a-7c9f-4faa-bca0-151ac96b02da" />

5. this is the default screen:

   <img width="1912" height="901" alt="image" src="https://github.com/user-attachments/assets/732739c6-d33c-427f-80a0-35ef8ddccd0c" />

6. Drang and drop the Webhook trigger:

   <img width="1909" height="919" alt="image" src="https://github.com/user-attachments/assets/e304cac9-c6d6-4d41-ab99-ed6efcb5d8b4" />

7. Select the webhook and rename it, also copy the webhook URI and save it as we will be connecting it to Wazuh-manager server:

      <img width="1894" height="927" alt="image" src="https://github.com/user-attachments/assets/5b500fc1-5984-4058-84c4-ad1fc2f60938" />

8. Click on change_me , remove hello world from Call section and add a runtime argument and then Save the workflow by clicking the Floppy disk icon:

      <img width="1876" height="978" alt="image" src="https://github.com/user-attachments/assets/39ee80f4-957a-4491-99e0-df381a09b399" />

9. To integrate the Shuffle with the wazuh-manager, add an Integration tag in the **"ossec.conf"** file. Open the **"ossec.conf"** file in powershell logged into wazuh server via ssh:

         nano /var/ossec/etc/ossec.conf      
      <img width="1100" height="635" alt="image" src="https://github.com/user-attachments/assets/e90cf7d4-d39e-40af-9fb4-75c3fc57c1f8" />
      
10. Copy the Integration tag and change it to your webhook URI, then paste the tag into the **"ossec.conf"** under global tag, be careful of indentation then save the file:

                 <integration>
               		<name>shuffle</name>
               		<rule_id>100002</rule_id>
               		<hook_url>http://IP:PORT/api/v1/hooks/webhook_hookid</hook_url>
               		<alert_format>json</alert_format>
               	</integration>
      <img width="1105" height="602" alt="image" src="https://github.com/user-attachments/assets/9dcbfffa-2362-47d3-a957-7558f61b9bc6" />

11. Restart the wazuh-manager

                   systemctl restart wazuh-manager

12. Go to the windows VM and re run mimikatz:

       <img width="923" height="169" alt="image" src="https://github.com/user-attachments/assets/bf020fc5-5436-4f22-bbbd-42c31346b9f3" />

13. On the Shuffle dashboard, select wazuh-alerts and start the webhook:

       <img width="1446" height="845" alt="image" src="https://github.com/user-attachments/assets/77fbc8b3-4fa5-4875-a408-036c7c2ec1b0" />

14. Click on show workflow run icon on bottom:

       <img width="1461" height="907" alt="image" src="https://github.com/user-attachments/assets/84e4fed8-a854-4ccf-aabf-cb372273c97d" />

15. Then click on **"Test workflow"**:

       <img width="1457" height="916" alt="image" src="https://github.com/user-attachments/assets/05536dcf-f3bf-4143-848d-41e2802cd130" />

16. Go back to all runs and you should see all results if you don't, refresh the runs or rerun mimikatz. The arrow will expand the debug window:

       <img width="1441" height="905" alt="image" src="https://github.com/user-attachments/assets/e884b891-87f0-40c1-9561-c6d29c6b5f68" />
       <img width="1456" height="911" alt="image" src="https://github.com/user-attachments/assets/9cdcccd9-051b-49f9-a157-e920b323c1cc" />
       <img width="1450" height="914" alt="image" src="https://github.com/user-attachments/assets/b3d8c9d1-aea9-4214-bf87-56e2b87742e1" />

> [!NOTE]
> You might have to execute mimikatz again and again to generate new alerts as you make changes to the workflow.

17. Expand the eventdata and you can see the hash value of the mimikatz. Explore this page and see what else can you use to identify the malware.

       <img width="1532" height="902" alt="image" src="https://github.com/user-attachments/assets/58e9c01f-04c7-48d8-b8fb-6526787c9131" />

18. To capture just the hash value, SHA256, we need to modify the change_me node settings:

       <img width="1458" height="897" alt="image" src="https://github.com/user-attachments/assets/0ec9667c-5e34-4ceb-8525-dac237112d4c" />

19. Refresh all runs and the alert should look like this:

       <img width="1441" height="884" alt="image" src="https://github.com/user-attachments/assets/868fe664-a987-4263-93e4-c0b8f4d38210" />

20. Make an account with VirusTotal to get the API key to integrate it with our workflow [VirusTotal signin](https://www.virustotal.com/gui/sign-in). Select API key from profile.

       <img width="1878" height="808" alt="image" src="https://github.com/user-attachments/assets/a43cc362-a2a6-45e2-bc02-b7d1f4f82d39" />

21. Copy the API key and return to the workflow. Search for VirusTotal and drag and drop the node:
    
       <img width="1299" height="693" alt="image" src="https://github.com/user-attachments/assets/2974475b-6b7f-4da5-bf2d-08293a9d5ead" />

22. Click on authenticate:

       <img width="1439" height="892" alt="image" src="https://github.com/user-attachments/assets/d16751a6-3a59-4151-a60b-5154dbde9adf" />

22. Paste your API key and submit:

       <img width="1496" height="899" alt="image" src="https://github.com/user-attachments/assets/b0f0f213-945e-437d-98d4-4d7e0b9e965a" />

23. Add the RegEx group to the VirusTotal node and set appropriate actions:

       <img width="1443" height="917" alt="image" src="https://github.com/user-attachments/assets/057b3503-2f12-49f3-ad95-498409f05beb" />

24. Go to Previous Runs, Select the last successful run and rerun it:

       <img width="1445" height="894" alt="image" src="https://github.com/user-attachments/assets/788f4b01-a45f-4300-9a0c-41d66a3317d3" />
       <img width="1442" height="906" alt="image" src="https://github.com/user-attachments/assets/360c7518-aa3d-423d-a9bc-2558deec7122" />
       <img width="1431" height="626" alt="image" src="https://github.com/user-attachments/assets/5c38b025-65b1-43d9-95e4-e35873f45abb" />

25. Scroll down and the VirusTotal node should have results:

       <img width="1422" height="926" alt="image" src="https://github.com/user-attachments/assets/c26b731e-bbc9-45dc-bbad-64f9385bf359" />

26. Expand the debug window and you should see **"attributes"**. Under it will be the reputation of the Hash.

       <img width="1494" height="905" alt="image" src="https://github.com/user-attachments/assets/409de1dc-924f-4648-848c-3a8f4b0457b7" />

27. Time to integrate TheHive with our workflow. Search TheHive and drag and drop it.

       <img width="1436" height="815" alt="image" src="https://github.com/user-attachments/assets/dcb86f00-719e-435d-a629-8be2c455be9f" />

28. Log into TheHive dashboard using default creds: **username:admin, Password:secret**

       <img width="1911" height="911" alt="image" src="https://github.com/user-attachments/assets/70a820a3-a01f-4767-a695-1949dc0a4e2c" />

29. Create a new organization and enter details. Then click **"Confirm"**

       <img width="1906" height="922" alt="image" src="https://github.com/user-attachments/assets/6a5014d0-4b99-45e5-bed5-659779c520d4" />

30. Click into the organization and add two users: one for the SOC Analyst (AKA you) and one for Shuffle (Service)

       <img width="1911" height="879" alt="image" src="https://github.com/user-attachments/assets/7dc82d7c-b437-4b3a-a7ea-26f2a4c62ba2" />
       <img width="1927" height="866" alt="image" src="https://github.com/user-attachments/assets/7c8a4df5-17f0-422a-a39f-aca2c6f94f58" />


31. Create an API key for shuffle to connect with TheHive save the API key somewhere for now:

       <img width="1891" height="607" alt="image" src="https://github.com/user-attachments/assets/171854a5-5f1f-4904-8451-09cf3f445f0e" />
       <img width="1896" height="853" alt="image" src="https://github.com/user-attachments/assets/3f57394e-a3c0-4d0b-afb1-e0a5b0171778" />

32. Go to the SOC Analyst user profile and set a password:

       <img width="1875" height="633" alt="image" src="https://github.com/user-attachments/assets/3e80a930-438d-4d8b-a6d9-51caecc26ce0" />
       <img width="1917" height="867" alt="image" src="https://github.com/user-attachments/assets/78ae552d-1e18-47d3-97fb-4998b5d25b09" />

33. Logout of admin and login with the SOC Analyst user we just created:

       <img width="1913" height="809" alt="image" src="https://github.com/user-attachments/assets/13ad1771-6176-4f73-9c25-530090f6dc6c" />

34. Head back to our workflow and authenticate Shuffle with TheHive. Enter the IP address of TheHive server:

       <img width="1507" height="920" alt="image" src="https://github.com/user-attachments/assets/c0c743b8-9397-4158-b6ef-851aa0613c9b" />

35. Connect TheHive with VirusTotal. Hover over the node and click the blue dot and drag the arrow to TheHive:

       <img width="1185" height="653" alt="image" src="https://github.com/user-attachments/assets/16b0e24a-fc68-4e77-8e51-742a688dd3ef" />
       <img width="963" height="774" alt="image" src="https://github.com/user-attachments/assets/0f10dedb-2ab5-4636-8c8a-3223178c36f7" />

36. Select TheHive node and configure it. At the writing of this readme, Shuffle is acting very buggy so we need to manually write an alert script in JSON bu selecting **"Advanced"**
    and then pasting the script there. i will include a script here so you can just paste and test :). Kept it minimum, feel free to experiment

               {
                 "title": "$exec.title",
                 "summary": "Mimikatz Usage detected on host $exec.text.win.system.computer with process ID $exec.text.win.system.processID and command line $exec.text.win.eventdata.commandLine",
                 "description": "Mimikatz Usage detected on host $exec.text.win.system.computer with process ID $exec.text.win.system.processID and command line $exec.text.win.eventdata.commandLine",
                 "type": "internal",
                 "source": "Wazuh",
                 "sourceRef": "$exec.rule_id",
                 "tags": ["T1003", "Credential Dumping"]
               }
 

       <img width="447" height="830" alt="image" src="https://github.com/user-attachments/assets/ab2d5672-c8f4-4ec3-b8c0-0dbd8d4f6001" />       

38. Allow all traffic on port 9000 in TheHive server firewall rule. This is a temporary rule to test.

       <img width="1220" height="283" alt="image" src="https://github.com/user-attachments/assets/dd8e4a08-861c-411e-b5f2-1dde81664b35" />

39. Rerun the workflow so you can check if an alert is being generated:

       <img width="1499" height="918" alt="image" src="https://github.com/user-attachments/assets/72289c2b-a025-4ed2-a568-7942544df7c9" />

40. Go to TheHive dashboard and expand the new cleated alert.

       <img width="1917" height="792" alt="image" src="https://github.com/user-attachments/assets/6cfa9eed-39cd-4a90-9d88-d6deba06482e" />

41. Search for **"Email"** and connect VirusTotal to it:

       <img width="1643" height="919" alt="image" src="https://github.com/user-attachments/assets/e8cb65c2-14fe-44b3-bc58-49fd9701a72c" />

42. Config example is like this: you can put your own email

       <img width="459" height="744" alt="image" src="https://github.com/user-attachments/assets/266cbb46-7b9b-401a-bb66-c7a52b6f5a64" />

43. And it pretty much works flawlessly:

       <img width="964" height="429" alt="image" src="https://github.com/user-attachments/assets/905a31c6-5429-49ff-9442-232bfd538fff" />
































       



 

 


      

























 














            
      
            

            
