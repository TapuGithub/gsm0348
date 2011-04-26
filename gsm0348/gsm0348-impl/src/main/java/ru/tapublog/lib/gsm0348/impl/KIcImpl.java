package ru.tapublog.lib.gsm0348.impl;

import javax.annotation.concurrent.Immutable;

import ru.tapublog.lib.gsm0348.api.header.commandpacket.GSM0348AlgorithmImplementation;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.KIc;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.ciphering.GSM0348CipheringAlgorithmMode;

/**
 * @author Victor Platov
 */
@Immutable
public class KIcImpl implements KIc
{

	private final byte m_data;

	public KIcImpl(byte data)
	{
		m_data = data;
	}

	@Override
	public GSM0348AlgorithmImplementation getAlgorithmImplementation()
	{
		return GSM0348AlgorithmImplementation.get((byte) (m_data & 0x3));
	}

	@Override
	public GSM0348CipheringAlgorithmMode getCipheringAlgorithmMode()
	{
		return GSM0348CipheringAlgorithmMode.get((byte) ((m_data & 0xC) >> 2));
	}

	@Override
	public byte getKeySetId()
	{
		return (byte) ((m_data & 0xF0) >>> 4);
	}

	public String toString()
	{
		return "KIc[algorithImplementation=" + getAlgorithmImplementation() + ", cipheringAlgorithmMode="
				+ getCipheringAlgorithmMode() + ", keySetId=" + getKeySetId() + ", raw=" + Util.toHex(m_data) + "]";
	}

	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof KIcImpl))
			return false;
		KIcImpl kici = (KIcImpl) obj;

		return m_data == kici.m_data;
	}

	public int hashCode()
	{
		int result = 42;
		result = 37 * result + m_data;
		return result;
	}
}
