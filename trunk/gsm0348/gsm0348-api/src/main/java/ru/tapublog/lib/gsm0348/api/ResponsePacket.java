package ru.tapublog.lib.gsm0348.api;

/**
 * This interface describes GSM 03.48 Response packet.
 * 
 * @author Victor Platov
 */
public interface ResponsePacket extends SecuredPacket
{
	/**
	 * Returns {@linkplain ResponsePacketHeader header} of this packet.
	 */
	ResponsePacketHeader getHeader();
}
