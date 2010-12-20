package ru.tapublog.lib.gsm0348.impl;

import javax.annotation.concurrent.Immutable;
import ru.tapublog.lib.gsm0348.impl.Util;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.GSM0348AlgorithmImplementation;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.KID;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.certificate.GSM0348CertificateAlgorithmMode;

/**
 * @author Victor Platov
 */
@Immutable
public class KIDImpl implements KID
{
	private final byte m_data;

	public KIDImpl(byte data)
	{
		m_data = data;
	}

	public GSM0348AlgorithmImplementation getAlgorithmImplementation()
	{
		return GSM0348AlgorithmImplementation.get((byte) (m_data & 0x3));
	}

	public GSM0348CertificateAlgorithmMode getCertificateAlgorithmMode()
	{
		return GSM0348CertificateAlgorithmMode.get((byte) ((m_data & 0xC) >> 2));
	}

	public byte getKeySetId()
	{
		return (byte) ((m_data & 0xF0) >>> 4);
	}

	public String toString()
	{
		return "KID[algorithImplementation=" + getAlgorithmImplementation() + ", certificateAlgorithmMode="
				+ getCertificateAlgorithmMode() + ", keySetId=" + getKeySetId() + ", raw=" + Util.toHex(m_data) + "]";
	}

	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof KIDImpl))
			return false;
		KIDImpl kidi = (KIDImpl) obj;
		return m_data == kidi.m_data;
	}

	public int hashCode()
	{
		int result = 42;
		result = 37 * result + m_data;
		return result;
	}
}
