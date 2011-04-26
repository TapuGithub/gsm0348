package ru.tapublog.lib.gsm0348.api;

/**
 * This interface describes GSM 03.48 packet.
 * 
 * @author Victor Platov
 */
public interface Packet
{
	/**
	 * Returns {@linkplain PacketData} of this packet.
	 */
	PacketData getData();

	/**
	 * Returns {@linkplain PacketHeader} of this packet.
	 */
	PacketHeader getHeader();

	byte[] toBytes();

	int getLength();
}
