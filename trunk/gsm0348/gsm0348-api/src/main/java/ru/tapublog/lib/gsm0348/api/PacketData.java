package ru.tapublog.lib.gsm0348.api;

/**
 * This interface describes data carried in {@linkplain Packet GSM 03.48
 * packets}.
 * 
 * @author Victor Platov
 */
public interface PacketData
{
	byte[] toBytes();

	int getLength();
}
