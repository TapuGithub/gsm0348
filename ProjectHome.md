## **If you have ANY questions - please [mail](mailto:tapumail@gmail.com) me** ##
# **Version 1.2.3 is out** #
  * Now you can download packaged versions from [External links](https://drive.google.com/folderview?id=0B6alWEH7mTrLSERoM2ZBRzVyczQ&usp=sharing) section
  * Fixed NPE during response packet recovering (thanks to Tomas)
  * Fixed testcases dataset schema location - now autotest should pass

## Demo wiki page - [DemoCode](DemoCode.md) ##

# Maven #
```
<repository>
   <id>GSM 03.48 Library</id>
   <url>http://gsm0348.googlecode.com/svn/trunk/repo</url>
</repository>
<dependencies>
   <dependency>
      <groupId>ru.tapublog.lib.gsm0348</groupId>
      <artifactId>gsm0348-api</artifactId>
      <version>1.2.3</version>
   </dependency>
   <dependency>
      <groupId>ru.tapublog.lib.gsm0348</groupId>
      <artifactId>gsm0348-impl</artifactId>
      <version>1.2.3</version>
   </dependency>
</dependencies>
```
# API and realization of GSM 03.48 standard for Java #

## Scope ##
The present project provides API and realization of the Secured Packets using Short Message Service Point to Point (SMS-PP). It is used to the exchange of secured packets between an entity in a GSM PLMN and an entity in the SIM. Secured Packets contain application messages to which certain mechanisms according to GSM 03.48 have been applied. Application messages are commands or data exchanged between an application resident in or behind the GSM PLMN and on the SIM.

## System Overview ##
![http://gsm0348.googlecode.com/files/1.png](http://gsm0348.googlecode.com/files/1.png)

<p>The Sending Application prepares an Application Message and forwards it to the Sending Entity, with an indication of the security to be applied to the message.</p>
<p>The Sending Entity prepends a Security Header (the Command Header) to the Application Message. It then applies the requested security to part of the Command Header and all of the Application Message, including any padding octets. The resulting structure is here referred to as the (Secured) Command Packet.</p>
<p>Under normal circumstances the Receiving Entity receives the Command Packet and unpacks it according to the security parameters indicated in the Command Header. The Receiving Entity subsequently forwards the Application Message to the Receiving Application indicating to the Receiving Application the security that was applied. The interface between the Sending Application and Sending Entity and the interface between the Receiving Entity and Receiving Application are proprietary.</p>
<p>If so indicated in the Command Header, the Receiving Entity shall create a (Secured) Response Packet. The Response Packet consists of a Security Header (the Response Header) and optionally, application specific data supplied by the Receiving Application. Both the Response Header and the application specific data are secured using the security mechanisms indicated in the received Command Packet. The Response Packet will be returned to the Sending Entity, subject to constraints in the transport layer, (e.g. timing).</p>
## The project ##
This project designed to help building Receiving/Sending Entity. It provides library for construction of Secured Packets with all required security procedures - signing and ciphering, padding, redundancy checking and etc.
## Capability ##

---

**Short Message Service Cell Broadcast (SMS-CB) isnot supported as for now.**




