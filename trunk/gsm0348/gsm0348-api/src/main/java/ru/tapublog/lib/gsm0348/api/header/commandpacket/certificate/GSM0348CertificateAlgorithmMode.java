package ru.tapublog.lib.gsm0348.api.header.commandpacket.certificate;

import org.apache.log4j.Logger;
/**
 * @author Victor Platov
 */
public enum GSM0348CertificateAlgorithmMode
{
	DES_CBC((byte) 0), TRIPLE_DES_CBC_2_KEYS((byte) 1), TRIPLE_DES_CBC_3_KEYS((byte) 2), RESERVED((byte) 3);

	private byte m_code;

	private GSM0348CertificateAlgorithmMode(byte code)
	{
		m_code = code;
	}

	public byte getCode()
	{
		return m_code;
	}

	public static GSM0348CertificateAlgorithmMode get(byte code)
	{
		switch (code)
		{
			case 0:
				return DES_CBC;
			case 1:
				return TRIPLE_DES_CBC_2_KEYS;
			case 2:
				return TRIPLE_DES_CBC_3_KEYS;
			case 3:
				return RESERVED;
			default:
				break;
		}
		Logger.getLogger(GSM0348CertificateAlgorithmMode.class).error("Certification algorithm mode with id=" + code + " not found");
		return null;
	}
}
