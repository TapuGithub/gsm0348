package ru.tapublog.lib.gsm0348.api.header.commandpacket.response;

import org.apache.log4j.Logger;

/**
 * @author Victor Platov
 */
public enum GSM0348PoRMode
{
	NO_REPLY((byte) 0), REPLY_ALWAYS((byte) 1), REPLY_WHEN_ERROR((byte) 2), RESERVED((byte) 3);

	private byte m_code;

	private GSM0348PoRMode(byte code)
	{
		m_code = code;
	}

	public byte getCode()
	{
		return m_code;
	}

	public static GSM0348PoRMode get(byte code)
	{
		switch (code)
		{
			case 0:
				return NO_REPLY;
			case 1:
				return REPLY_ALWAYS;
			case 2:
				return REPLY_WHEN_ERROR;
			case 3:
				return RESERVED;
			default:
				break;
		}
		Logger.getLogger(GSM0348PoRMode.class).error("PoR mode with id=" + code + " not found");
		return null;
	}
}
