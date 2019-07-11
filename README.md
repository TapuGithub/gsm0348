# API and realization of GSM 03.48 (ETSI TS 102 225) standard for Java

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.opentelecoms.gsm0348/gsm0348/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.opentelecoms.gsm0348/gsm0348)

## Scope
The project provides API and realization of the Secured Packets using Short Message Service Point to Point (SMS-PP). It is used to the exchange of secured packets between an entity in a GSM PLMN and an entity in the SIM. Secured Packets contain application messages to which certain mechanisms according to GSM 03.48 have been applied.
Application messages are commands or data exchanged between an application resident in or behind the GSM PLMN and on the SIM.

## History
The project was originally developed by Victor Platov. Initially the code was hosted on Google Code (https://code.google.com/archive/p/gsm0348/). After Google shutdown Google Code, the code was moved to GitHub (https://github.com/TapuGithub/gsm0348).
Finally, the code was adopted by the Open Telecoms project.

## News

0. Moved to GitHub - as you all know Google Code is closing
0. Version 1.2.7 is out
0. Fixed NPE during response packet recovering (thanks to Tomas)
0. Fixed testcases dataset schema location - now autotest should pass
0. Added AES and RC
0. Moved to the Open Telecoms GitHub and published in Maven Central repository

## System Overview

The Sending Application prepares an Application Message and forwards it to the Sending Entity, with an indication of the security to be applied to the message. The Sending Entity prepends a Security Header (the Command Header) to the Application Message. It then applies the requested security to part of the Command Header and all of the Application Message, including any padding octets. The resulting structure is here referred to as the (Secured) Command Packet.

Under normal circumstances the Receiving Entity receives the Command Packet and unpacks it according to the security parameters indicated in the Command Header. The Receiving Entity subsequently forwards the Application Message to the Receiving Application indicating to the Receiving Application the security that was applied. The interface between the Sending Application and Sending Entity and the interface between the Receiving Entity and Receiving Application are proprietary.

If so indicated in the Command Header, the Receiving Entity shall create a (Secured) Response Packet. The Response Packet consists of a Security Header (the Response Header) and optionally, application specific data supplied by the Receiving Application. Both the Response Header and the application specific data are secured using the security mechanisms indicated in the received Command Packet. The Response Packet will be returned to the Sending Entity, subject to constraints in the transport layer, (e.g. timing).

![System overview](/resources/system-overview.png?raw=true "System overview")

### The project
This project designed to help building Receiving/Sending Entity. It provides library for construction of Secured Packets with all required security procedures - signing and ciphering, padding, redundancy checking and etc.

### Capability
Short Message Service Cell Broadcast (SMS-CB) is not supported as for now.

### Links
![3GPP TS 31.115](https://www.etsi.org/deliver/etsi_ts/131100_131199/131115/06.05.00_60/ts_131115v060500p.pdf)

### Maven Config
```
<repository>
   <id>GSM 03.48 Library</id>
   <url>https://github.com/opentelecoms-org/gsm0348</url>
</repository>
<dependencies>
   <dependency>
      <groupId>org.opentelecoms.gsm0348</groupId>
      <artifactId>gsm0348-api</artifactId>
      <version>1.2.9</version>
   </dependency>
   <dependency>
      <groupId>org.opentelecoms.gsm0348</groupId>
      <artifactId>gsm0348-impl</artifactId>
      <version>1.2.9</version>
   </dependency>
</dependencies>
```

### Maven Central Release
For a snapshot:
```
mvn clean deploy
```
For a proper release:
```
mvn versions:set -DnewVersion=1.2.8
mvn clean deploy -P release
mvn nexus-staging:release
# Or when something went wrong
mvn nexus-staging:drop
```