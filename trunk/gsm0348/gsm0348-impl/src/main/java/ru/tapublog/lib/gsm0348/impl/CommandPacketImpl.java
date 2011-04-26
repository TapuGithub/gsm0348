package ru.tapublog.lib.gsm0348.impl;

import javax.annotation.concurrent.Immutable;

import ru.tapublog.lib.gsm0348.api.CommandPacket;
import ru.tapublog.lib.gsm0348.api.CommandPacketHeader;
import ru.tapublog.lib.gsm0348.api.PacketData;
/**
 * @author Victor Platov
 */
@Immutable
public final class CommandPacketImpl implements CommandPacket
{

	private final PacketData m_data;
	private final CommandPacketHeader m_header;

	public CommandPacketImpl(CommandPacketHeader header, PacketData data)
	{
		if(header == null || data == null )
			throw new IllegalArgumentException("data and header cannot be null");
		
		m_data = data;
		m_header = header;
	}

	@Override
	public PacketData getData()
	{
		return m_data;
	}

	@Override
	public byte[] toBytes()
	{
		int length = getLength();
		byte[] result = new byte[length];
		result[0] = (byte) (((length - 2) & 0xFF) >> 8);
		result[1] = (byte) (((length - 2) & 0xFF));
		System.arraycopy(m_header.toBytes(), 0, result, 2, m_header.getLength());
		System.arraycopy(m_data.toBytes(), 0, result, 2 + m_header.getLength(), m_data.getLength());
		return result;
	}

	@Override
	public int getLength()
	{
		return 2 + m_data.getLength() + m_header.getLength();
	}

	@Override
	public CommandPacketHeader getHeader()
	{
		return m_header;
	}

	public String toString()
	{
		return "CommandPacket[length=" + getLength() + ", " + m_header + ", " + m_data + "]";
	}
	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof CommandPacketImpl))
			return false;
		CommandPacketImpl cpi = (CommandPacketImpl) obj;
		return m_data.equals(cpi.m_data) && m_header.equals(cpi.m_header);
	}

	public int hashCode()
	{
		int result = 42;
		result = 37 * result + m_data.hashCode();
		result = 37 * result + m_header.hashCode();
		return result;
	}
}
