# PortVulnScan
PortVulnScan is a Tool to scan Ports it's Services, Versions and Vulnerabilities if avaiable.

## How to Install

<ol>
<li>Clone the repository:</li>
  
```
git clone https://github.com/Aseer-Bazal/PortVulnScan.git
```
<li>Move into the tool directory:</li>

```
cd PortVulnScan
```
<li>Create a Python virtual environment:</li>
<P>It is recommended to use a virtual environment to avoid dependency conflicts.</P>

```
python3 -m venv venv
```
<li>Activate the virtual environment:</li> 

```
source venv/bin/activate
```
<li>Install the required libraries:</li> 

```
pip install -r requirements.txt
```
</ol>

## How to Use
Execute the tool in a Python environment
```
python3 PortVulnScan.py
```
<ol>
<li>Target IP Address: 192.168.1.1</li>
<li>Port Range: 1-1024</li>
<li>Vulners API Key: your_vulners_api_key_here</li>
</ol>

## How to Obtain Vulners Api Key
Please, sign up at <a href="https://vulners.com/">Vulners</a> website. Go to the personal menu by clicking on your name in the left bottom corner. Follow "API KEYS" tab. Generate an API key with scope "api" 

<a href="https://vulners.com/docs/api_reference/apikey/">Step by step guide for vulners api key</a>

## Exiting and Deactivating the Environment
After using the tool, you can deactivate the virtual environment:
```
deactivate```






