package ru.tapublog.lib.gsm0348.impl;

import javax.annotation.concurrent.Immutable;
import ru.tapublog.lib.gsm0348.impl.Util;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.CommandSPI;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.certificate.GSM0348CertificateMode;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.synchronization.GSM0348SynchroCounterMode;

/**
 * @author Victor Platov
 */
@Immutable
public final class CommandSPIImpl implements CommandSPI
{
	private final byte m_data;

	public CommandSPIImpl(byte data)
	{
		m_data = data;
	}

	public GSM0348CertificateMode getCertificateMode()
	{
		return GSM0348CertificateMode.get((byte) (m_data & 0x3));
	}

	public GSM0348SynchroCounterMode getSynchroCounterMode()
	{
		return GSM0348SynchroCounterMode.get((byte) ((m_data & 0x18) >> 3));
	}

	public boolean isCiphered()
	{
		return ((m_data & 0x4) != 0);
	}

	public String toString()
	{
		return "SPI[certificateMode=" + getCertificateMode() + ", countersMode=" + getSynchroCounterMode() + ", isCiphered="
				+ isCiphered() + ", raw=" + Util.toHex(m_data) + "]";
	}

	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof CommandSPIImpl))
			return false;
		CommandSPIImpl cspii = (CommandSPIImpl) obj;
		return m_data == cspii.m_data;
	}

	public int hashCode()
	{
		int result = 42;
		result = 37 * result + m_data;
		return result;
	}
}
