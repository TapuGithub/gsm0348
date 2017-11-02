** If you have ANY questions - please mail me(tapumail@gmail.com)**

# API and realization of GSM 03.48 standard for Java
## Scope
The present project provides API and realization of the Secured Packets using Short Message Service Point to Point (SMS-PP). It is used to the exchange of secured packets between an entity in a GSM PLMN and an entity in the SIM. Secured Packets contain application messages to which certain mechanisms according to GSM 03.48 have been applied. Application messages are commands or data exchanged between an application resident in or behind the GSM PLMN and on the SIM.

## News

0. Moved to GitHub - as you all know Google Code is closing
0. Version 1.2.5 is out
0. Fixed NPE during response packet recovering (thanks to Tomas)
0. Fixed testcases dataset schema location - now autotest should pass
0. Added AES and RC

## System Overview

The Sending Application prepares an Application Message and forwards it to the Sending Entity, with an indication of the security to be applied to the message. The Sending Entity prepends a Security Header (the Command Header) to the Application Message. It then applies the requested security to part of the Command Header and all of the Application Message, including any padding octets. The resulting structure is here referred to as the (Secured) Command Packet.

Under normal circumstances the Receiving Entity receives the Command Packet and unpacks it according to the security parameters indicated in the Command Header. The Receiving Entity subsequently forwards the Application Message to the Receiving Application indicating to the Receiving Application the security that was applied. The interface between the Sending Application and Sending Entity and the interface between the Receiving Entity and Receiving Application are proprietary.

If so indicated in the Command Header, the Receiving Entity shall create a (Secured) Response Packet. The Response Packet consists of a Security Header (the Response Header) and optionally, application specific data supplied by the Receiving Application. Both the Response Header and the application specific data are secured using the security mechanisms indicated in the received Command Packet. The Response Packet will be returned to the Sending Entity, subject to constraints in the transport layer, (e.g. timing).

![System overview](http://gsm0348.googlecode.com/files/1.png)

### The project
This project designed to help building Receiving/Sending Entity. It provides library for construction of Secured Packets with all required security procedures - signing and ciphering, padding, redundancy checking and etc.

### Capability
Short Message Service Cell Broadcast (SMS-CB) is not supported as for now.

### Maven Config
``
<repository>
   <id>GSM 03.48 Library</id>
   <url>https://github.com/pmoerenhout/gsm0348</url>
</repository>
<dependencies>
   <dependency>
      <groupId>ru.tapublog.lib.gsm0348</groupId>
      <artifactId>gsm0348-api</artifactId>
      <version>1.2.5</version>
   </dependency>
   <dependency>
      <groupId>ru.tapublog.lib.gsm0348</groupId>
      <artifactId>gsm0348-impl</artifactId>
      <version>1.2.5</version>
   </dependency>
</dependencies>
```
