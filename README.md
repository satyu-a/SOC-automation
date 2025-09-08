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


            

            
