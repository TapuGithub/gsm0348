package ru.tapublog.lib.gsm0348.impl;

import javax.annotation.concurrent.Immutable;
import ru.tapublog.lib.gsm0348.api.PacketData;
import ru.tapublog.lib.gsm0348.api.ResponsePacket;
import ru.tapublog.lib.gsm0348.api.ResponsePacketHeader;

/**
 * @author Victor Platov
 */
@Immutable
public final class ResponsePacketImpl extends SecuredPacketImpl implements ResponsePacket
{
	public ResponsePacketImpl(ResponsePacketHeader header, PacketData data)
	{
		super(header, data);
	}

	public ResponsePacketHeader getHeader()
	{
		return (ResponsePacketHeader) super.getHeader();
	}

	public String toString()
	{
		return "Response" + super.toString();
	}

	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof ResponsePacketImpl))
			return false;
		ResponsePacketImpl rpi = (ResponsePacketImpl) obj;
		return getHeader().equals(rpi.getHeader())
				&& (getData() == null ? rpi.getData() == null : getData().equals(rpi.getData()));
	}

	public int hashCode()
	{
		int result = 42;
		result = 37 * result + getHeader().hashCode();
		result = 37 * result + (getData() == null ? 0 : getData().hashCode());
		return result;
	}
}
