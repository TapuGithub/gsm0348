package ru.tapublog.lib.gsm0348.api.header;

/**
 * This interface describes GSM 03.48 Toolkit Application Reference.
 * 
 * @author Victor Platov
 */
public interface TAR
{
	byte[] toBytes();

	int getLength();
}
