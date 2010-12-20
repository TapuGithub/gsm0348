package ru.tapublog.lib.gsm0348.api.header.commandpacket.synchronization;

import org.apache.log4j.Logger;

/**
 * @author Victor Platov
 */
public enum GSM0348SynchroCounterMode
{
	NO_COUNTER((byte) 0), COUNTER_NO_REPLAY_NO_CHECK((byte) 1), COUNTER_REPLAY_OR_CHECK((byte) 2), COUNTER_REPLAY_OR_CHECK_INCREMENT(
			(byte) 3);

	private byte m_code;

	private GSM0348SynchroCounterMode(byte code)
	{
		m_code = code;
	}

	public byte getCode()
	{
		return m_code;
	}

	public static GSM0348SynchroCounterMode get(byte code)
	{
		switch (code)
		{
			case 0:
				return NO_COUNTER;
			case 1:
				return COUNTER_NO_REPLAY_NO_CHECK;
			case 2:
				return COUNTER_REPLAY_OR_CHECK;
			case 3:
				return COUNTER_REPLAY_OR_CHECK_INCREMENT;
			default:
				break;
		}
		Logger.getLogger(GSM0348SynchroCounterMode.class).error("Synchro counter mode with id=" + code + " not found");
		return null;
	}
}
