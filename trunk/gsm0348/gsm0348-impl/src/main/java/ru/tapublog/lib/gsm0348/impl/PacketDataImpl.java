package ru.tapublog.lib.gsm0348.impl;

import javax.annotation.concurrent.Immutable;

import ru.tapublog.lib.gsm0348.api.PacketData;

/**
 * @author Victor Platov
 */
@Immutable
public final class PacketDataImpl implements PacketData
{
	private final byte[] m_data;

	public PacketDataImpl(byte[] data)
	{
		if (data == null)
			throw new IllegalArgumentException("data cannot be null");
		m_data = data.clone();
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

	public String toString()
	{
		return "PacketData[length=" + m_data.length + ",data=" + Util.toHexArray(m_data) + "]";
	}

	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof PacketDataImpl))
			return false;
		PacketDataImpl pdi = (PacketDataImpl) obj;
		if (m_data.length != pdi.m_data.length)
			return false;
		for (int i = 0; i < m_data.length; i++)
			if (m_data[i] != pdi.m_data[i])
				return false;

		return true;
	}

	public int hashCode()
	{
		int result = 42;
		for (int i = 0; i < m_data.length; i++)
			result = 37 * result + m_data[i];
		return result;
	}
}
