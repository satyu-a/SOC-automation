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

## Procedure
1. Windows installation with Sysmon configuration
2. Ubuntu server installation on Vultr
3. Wazuh installation
4. TheHive installation
5. Shuffle installation
6. Tools Configuration
