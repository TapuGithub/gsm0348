package ru.tapublog.lib.gsm0348.api.header.commandpacket.response;

import org.apache.log4j.Logger;
/**
 * @author Victor Platov
 */
public enum GSM0348PoRProtocol
{
	SMS_DELIVER_REPORT((byte)0),SMS_SUBMIT((byte)1);

	private byte m_code;

	private GSM0348PoRProtocol(byte code)
	{
		m_code = code;
	}

	public byte getCode()
	{
		return m_code;
	}

	public static GSM0348PoRProtocol get(byte code)
	{
		switch (code)
		{
			case 0:
				return SMS_DELIVER_REPORT;
			case 1:
				return SMS_SUBMIT;
			default:
				break;
		}
		Logger.getLogger(GSM0348PoRProtocol.class).error("PoR protocol with id=" + code + " not found");
		return null;
	}
}
