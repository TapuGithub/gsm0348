package ru.tapublog.lib.gsm0348.impl;

import javax.annotation.concurrent.Immutable;

import ru.tapublog.lib.gsm0348.api.CommandPacketHeader;
import ru.tapublog.lib.gsm0348.api.header.Counters;
import ru.tapublog.lib.gsm0348.api.header.TAR;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.KID;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.KIc;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.SPI;

/**
 * @author Victor Platov
 */
@Immutable
public final class CommandPacketHeaderImpl implements CommandPacketHeader
{

	private final byte[] m_data;
	private final int m_securityLength;

	public CommandPacketHeaderImpl(byte[] data, int securityLength)
	{
		if (data == null || data.length < 14)
			throw new IllegalArgumentException("data cannot be null or have length less than 14");

		m_data = data.clone();
		m_securityLength = securityLength;
	}

	@Override
	public TAR getTAR()
	{
		byte[] tar = new byte[3];
		System.arraycopy(m_data, 5, tar, 0, 3);
		return new TARImpl(tar);
	}

	@Override
	public byte getPaddingCounter()
	{
		return m_data[13];
	}

	@Override
	public byte[] getSecurity()
	{
		byte[] security = new byte[m_securityLength];
		System.arraycopy(m_data, m_data.length - m_securityLength, security, 0, m_securityLength);
		return security;
	}

	@Override
	public Counters getCounters()
	{
		byte[] counters = new byte[5];
		System.arraycopy(m_data, 8, counters, 0, 5);
		return new CountersImpl(counters);
	}

	@Override
	public byte[] toBytes()
	{
		return m_data.clone();
	}

	@Override
	public int getLength()
	{
		return m_data.length;
	}

	@Override
	public SPI getSPI()
	{
		return new SPIImpl(new CommandSPIImpl(m_data[1]), new ResponseSPIImpl(m_data[2]));
	}

	@Override
	public KIc getKIc()
	{
		return new KIcImpl(m_data[3]);
	}

	@Override
	public KID getKID()
	{
		return new KIDImpl(m_data[4]);
	}

	public String toString()
	{
		return "CommandPacketHeader[length=" + getLength() + ", " + getSPI() + ", " + getKIc() + ", " + getKID() + ", "
				+ getTAR() + ", " + getCounters() + ", paddingCounter=" + Util.toHex(getPaddingCounter()) + ", security="
				+ Util.toHexArray(getSecurity()) + "]";
	}

	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof CommandPacketHeaderImpl))
			return false;
		CommandPacketHeaderImpl cphi = (CommandPacketHeaderImpl) obj;
		if (m_data.length != cphi.m_data.length)
			return false;
		for (int i = 0; i < m_data.length; i++)
			if (m_data[i] != cphi.m_data[i])
				return false;

		return m_securityLength == cphi.m_securityLength;
	}

	public int hashCode()
	{
		int result = 42;
		result = 37 * result + m_securityLength;
		for (int i = 0; i < m_data.length; i++)
			result = 37 * result + m_data[i];
		return result;
	}
}
