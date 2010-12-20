package ru.tapublog.lib.gsm0348.api.header.responsepacket;

import org.apache.log4j.Logger;

/**
 * This interface describes GSM 03.48 Response status codes.
 * 
 * @author Victor Platov
 */
public enum GSM0348ResponsePacketStatusCode
{
	PoR_OK((byte) 0), RC_CC_DS_FAILED((byte) 1), CNTR_LOW((byte) 2), CNTR_HIGH((byte) 3), CNTR_BLOCKED((byte) 4), CIPHERING_ERROR(
			(byte) 5), UNIDENTIFIED_SECURITY_ERROR((byte) 6), INSUFFICIENT_MEMORY((byte) 7), MORE_TIME((byte) 8), TAR_UNKNOWN(
			(byte) 9), UNKOWN((byte) -1);

	private byte m_code;

	private GSM0348ResponsePacketStatusCode(byte code)
	{
		m_code = code;
	}

	public byte getCode()
	{
		return m_code;
	}

	public static GSM0348ResponsePacketStatusCode get(byte code)
	{
		switch (code)
		{
			case 0:
				return PoR_OK;
			case 1:
				return RC_CC_DS_FAILED;
			case 2:
				return CNTR_LOW;
			case 3:
				return CNTR_HIGH;
			case 4:
				return CNTR_BLOCKED;
			case 5:
				return CIPHERING_ERROR;
			case 6:
				return UNIDENTIFIED_SECURITY_ERROR;
			case 7:
				return INSUFFICIENT_MEMORY;
			case 8:
				return MORE_TIME;
			case 9:
				return TAR_UNKNOWN;
			default:
				Logger.getLogger(GSM0348ResponsePacketStatusCode.class).warn("Certification mode with id=" + code + " not found");
				return UNKOWN;
		}
	}
}
