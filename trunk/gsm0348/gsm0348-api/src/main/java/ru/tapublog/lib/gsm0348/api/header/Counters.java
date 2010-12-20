package ru.tapublog.lib.gsm0348.api.header;
/**
 * This interface describes GSM 03.48 Counters. 
 * 
 * @author Victor Platov
 */
public interface Counters
{
	byte[] toBytes();
	int getLength();
}
