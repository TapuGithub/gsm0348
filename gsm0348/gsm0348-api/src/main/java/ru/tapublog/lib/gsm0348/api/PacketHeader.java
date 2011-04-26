package ru.tapublog.lib.gsm0348.api;

/**
 * This interface describes {@linkplain Packet GSM 03.48 packet} header.
 * 
 * @author Victor Platov
 */
public interface PacketHeader
{
	byte[] toBytes();

	int getLength();
}
