package ru.tapublog.lib.gsm0348.api;
/**
 * This interface describes GSM 03.48 Secured packet. It is used both for
 * command and response packets.
 * 
 * @author Victor Platov
 */
public interface SecuredPacket extends Packet
{
	/**
	 * Return packet`s header.
	 */
	SecurityHeader getHeader();
	/**
	 * Return packet`s data.
	 */
	PacketData getData();
}
