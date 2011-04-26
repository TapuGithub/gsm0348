package ru.tapublog.lib.gsm0348.impl;

import javax.annotation.concurrent.Immutable;

import ru.tapublog.lib.gsm0348.api.PacketData;
import ru.tapublog.lib.gsm0348.api.SecuredPacket;
import ru.tapublog.lib.gsm0348.api.SecurityHeader;

/**
 * @author Victor Platov
 */
@Immutable
public abstract class SecuredPacketImpl implements SecuredPacket
{

	private final PacketData m_data;
	private final SecurityHeader m_header;

	public SecuredPacketImpl(SecurityHeader header, PacketData data)
	{
		if (header == null || data == null)
			throw new IllegalArgumentException("data and header cannot be null");

		m_data = data;
		m_header = header;
	}

	@Override
	public PacketData getData()
	{
		return m_data;
	}

	public int getLength()
	{
		return m_header.getLength() + m_data.getLength() + 2;
	}

	public byte[] toBytes()
	{
		final int packetLength = getLength();
		byte[] result = new byte[packetLength];
		final byte[] data = m_data.toBytes();
		final byte[] header = m_header.toBytes();
		result[0] = (byte) (((packetLength - 2) & 0xFF) >> 8);
		result[1] = (byte) (((packetLength - 2) & 0xFF));
		System.arraycopy(header, 0, result, 2, header.length);
		System.arraycopy(data, 0, result, 2 + header.length, data.length);
		return result;
	}

	@Override
	public SecurityHeader getHeader()
	{
		return m_header;
	}

	public String toString()
	{
		return "Packet[" + m_header + ", " + m_data + "]";
	}

	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof SecuredPacketImpl))
			return false;
		SecuredPacketImpl spi = (SecuredPacketImpl) obj;
		return getHeader().equals(spi.getHeader()) && getData().equals(spi.getData());
	}

	public int hashCode()
	{
		int result = 42;
		result = 37 * result + getHeader().hashCode();
		result = 37 * result + getData().hashCode();
		return result;
	}
}
