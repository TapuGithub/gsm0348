package ru.tapublog.lib.gsm0348.api.header.commandpacket.certificate;

import org.apache.log4j.Logger;

/**
 * @author Victor Platov
 */
public enum GSM0348CertificateMode
{
	NO_SECURITY((byte) 0), RC((byte) 1), CC((byte) 2), DS((byte) 3);

	private byte m_code;

	private GSM0348CertificateMode(byte code)
	{
		m_code = code;
	}

	public byte getCode()
	{
		return m_code;
	}

	public static GSM0348CertificateMode get(byte code)
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
		Logger.getLogger(GSM0348CertificateMode.class).error("Certification mode with id=" + code + " not found");
		return null;
	}

}
