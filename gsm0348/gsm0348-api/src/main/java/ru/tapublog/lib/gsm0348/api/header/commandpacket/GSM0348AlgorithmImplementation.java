package ru.tapublog.lib.gsm0348.api.header.commandpacket;

import org.apache.log4j.Logger;
/**
 * @author Victor Platov
 */
public enum GSM0348AlgorithmImplementation
{
	ALGORITHM_KNOWN_BY_BOTH_ENTITIES((byte) 0), DES((byte) 1), RESERVED((byte) 2), PROPRIETARY_IMPLEMENTATIONS((byte) 3);

	private byte m_code;

	private GSM0348AlgorithmImplementation(byte code)
	{
		m_code = code;
	}

	public byte getCode()
	{
		return m_code;
	}

	public static GSM0348AlgorithmImplementation get(byte code)
	{
		switch (code)
		{
			case 0:
				return ALGORITHM_KNOWN_BY_BOTH_ENTITIES;
			case 1:
				return DES;
			case 2:
				return RESERVED;
			case 3:
				return PROPRIETARY_IMPLEMENTATIONS;
			default:
				break;
		}
		Logger.getLogger(GSM0348AlgorithmImplementation.class).error("Algorithm implementation with id=" + code + " not found");
		return null;
	}
}
