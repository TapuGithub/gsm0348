package ru.tapublog.lib.gsm0348.impl;

import javax.annotation.concurrent.Immutable;
import ru.tapublog.lib.gsm0348.impl.Util;
import ru.tapublog.lib.gsm0348.api.header.Counters;

/**
 * @author Victor Platov
 */
@Immutable
public final class CountersImpl implements Counters
{
	private final byte[] m_data;

	public CountersImpl(byte[] data)
	{
		if (data == null)
			throw new IllegalArgumentException("data cannot be null");
		m_data = data.clone();
	}

	public byte[] toBytes()
	{
		return m_data.clone();
	}

	public int getLength()
	{
		return m_data.length;
	}

	public String toString()
	{
		return "Counters=[" + Util.toHexArray(m_data) + "]";
	}

	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof CountersImpl))
			return false;
		CountersImpl ci = (CountersImpl) obj;
		if (m_data.length != ci.m_data.length)
			return false;
		for (int i = 0; i < m_data.length; i++)
			if (m_data[i] != ci.m_data[i])
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
