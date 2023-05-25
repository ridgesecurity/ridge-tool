# Ridge API Auto Testing Tool Documentation

## Introduction

This is an inital implementaion of RidgeBot Auto API Testing Tool

## Table of Contents

- [Local Dependency Setup](#local-dependency-setup)
    - [Certificate Setup](#certificate-setup)
        - [Mac](#mac)
        - [Windows](#windows)
- [Running](#running)

## Local Dependency Setup

### Certificate Setup

You must install the Ridge ca.crt certificate on your device to be able to capture secure HTTPS traffic. First, create a **Website Penetration** task and set up the proxy in RidgeBot. The attack target should coincide with the provided server url in the swagger file. Then follow the instructions below to install the required security certificate on your devices.

#### Mac

1. From RidgeBot, access task-topology-task operation-proxy, and download the certificate 
    ![cert_down](img/cert_down.png)

2. Select **System** in the **Keychain** list, and then select **Add**. Enter your system password to confirm the action.

3. In Keychain Access, double-click the imported certificate to open it.

4. Expand the Trust section. Select the option to Always Trust when using this certificate, and make sure Always Trust is selected for Secure Sockets Layer(SSL). 
    -![cert_example](img/trust_mac.png)


#### Windows

1. From RidgeBot, access task-topology-task operation-proxy, and download the certificate 
    ![cert_down](img/cert_down.png)

2. Right-click on the **ca.crt** file and select **Install Certificate**.

3. Select **Local Machine** and select **Next**. This action requires Administrator permissions. Select **Yes** to proceed.

4. Select **Place all certificates in the following store**.

5. Select **Browse** and then select **Trusted Root Certification Authorities**.

6. Select **OK** and then select **Next**.

7. Select Finish to import the **certificate**.

## Running

### Api Command File

```
Usage: python3 api_conv.py [api_commands] [-p 'http://proxy_server:port'] [-f conv#]

python3 api_conv.py citcon_api.txt -p 'http://66.220.31.58:64194' -f 1
```
Api_conv.py requires a txt document of curl commands and a proxy server.


### Swagger File
```
Usage: python3 swagger_conv.py [swagger_file] [-p 'http://proxy_server:port'] [-f conv#]

python3 swagger_conv.py petstore.yaml -p 'http://66.220.31.58:64194' -f 1 -a 'keyabcd1234'

python3 swagger_conv.py petstore.json -p 'http://66.220.31.58:64194' 
```
Swagger file should be yaml or json file.


For Ridgebot the addresss is : 66.220.31.58

The proxy should be opened when running the code.

The port can be found in the window of the proxy in ridgebot 
    ![proxy_port](img/proxy_port.png)

See -help for further documentaion
