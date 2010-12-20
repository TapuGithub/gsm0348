package ru.tapublog.lib.gsm0348.impl;

import javax.annotation.concurrent.Immutable;
import ru.tapublog.lib.gsm0348.impl.Util;
import ru.tapublog.lib.gsm0348.api.ResponsePacketHeader;
import ru.tapublog.lib.gsm0348.api.header.Counters;
import ru.tapublog.lib.gsm0348.api.header.TAR;
import ru.tapublog.lib.gsm0348.api.header.responsepacket.GSM0348ResponsePacketStatusCode;

/**
 * @author Victor Platov
 */
@Immutable
public final class ResponsePacketHeaderImpl implements ResponsePacketHeader
{
	private final byte[] m_data;
	private final int m_securityLength;

	public ResponsePacketHeaderImpl(byte[] data, int securityLength)
	{
		if (data == null || data.length < 11)
			throw new IllegalArgumentException("data cannot be null or have length less than 11");

		m_data = data.clone();
		m_securityLength = securityLength;
	}

	public TAR getTAR()
	{
		byte[] tar = new byte[3];
		System.arraycopy(m_data, 1, tar, 0, 3);
		return new TARImpl(tar);
	}

	public byte getPaddingCounter()
	{
		return m_data[9];
	}

	public byte[] getSecurity()
	{
		byte[] security = new byte[m_securityLength];
		System.arraycopy(m_data, m_data.length - m_securityLength, security, 0, m_securityLength);
		return security;
	}

	public Counters getCounters()
	{
		byte[] counters = new byte[5];
		System.arraycopy(m_data, 4, counters, 0, 5);
		return new CountersImpl(counters);
	}

	public byte[] toBytes()
	{
		return m_data.clone();
	}

	public int getLength()
	{
		return m_data.length;
	}

	public GSM0348ResponsePacketStatusCode getResponseStatus()
	{
		return GSM0348ResponsePacketStatusCode.get(m_data[10]);
	}

	public String toString()
	{
		return "ResponsePacketHeader[length=" + getLength() + ", responseCode=" + getResponseStatus() + ", " + getTAR() + ", "
				+ getCounters() + ", paddingCounter=" + Util.toHex(getPaddingCounter()) + ", security="
				+ Util.toHexArray(getSecurity()) + "]";
	}

	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof ResponsePacketHeaderImpl))
			return false;
		ResponsePacketHeaderImpl rphi = (ResponsePacketHeaderImpl) obj;
		if (m_data.length != rphi.m_data.length)
			return false;
		for (int i = 0; i < m_data.length; i++)
			if (m_data[i] != rphi.m_data[i])
				return false;
		return m_securityLength == rphi.m_securityLength;
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
