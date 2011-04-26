package ru.tapublog.lib.gsm0348.api;

/**
 * This interface describes GSM 03.48 Command packet.
 * 
 * @author Victor Platov
 */
public interface CommandPacket extends SecuredPacket
{
	/**
	 * Returns {@linkplain CommandPacketHeader header} of this packet.
	 */
	CommandPacketHeader getHeader();
}
