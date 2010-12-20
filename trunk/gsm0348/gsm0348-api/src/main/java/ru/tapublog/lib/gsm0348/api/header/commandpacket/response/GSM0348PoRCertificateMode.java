package ru.tapublog.lib.gsm0348.api.header.commandpacket.response;

import org.apache.log4j.Logger;
/**
 * @author Victor Platov
 */
public enum GSM0348PoRCertificateMode
{
	NO_SECURITY((byte) 0), RC((byte) 1), CC((byte) 2), DS((byte) 3);

	private byte m_code;

	private GSM0348PoRCertificateMode(byte code)
	{
		m_code = code;
	}

	public byte getCode()
	{
		return m_code;
	}

	public static GSM0348PoRCertificateMode get(byte code)
	{
		switch (code)
		{
			case 0:
				return NO_SECURITY;
			case 1:
				return RC;
			case 2:
				return CC;
			case 3:
				return DS;
			default:
				break;
		}
		Logger.getLogger(GSM0348PoRCertificateMode.class).error("PoR certification mode with id=" + code + " not found");
		return null;
	}
}
