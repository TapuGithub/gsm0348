package ru.tapublog.lib.gsm0348.impl;

import javax.annotation.concurrent.Immutable;
import ru.tapublog.lib.gsm0348.impl.Util;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.ResponseSPI;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.response.GSM0348PoRCertificateMode;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.response.GSM0348PoRMode;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.response.GSM0348PoRProtocol;

/**
 * @author Victor Platov
 */
@Immutable
public final class ResponseSPIImpl implements ResponseSPI
{
	private final byte m_data;

	public ResponseSPIImpl(byte data)
	{
		m_data = data;
	}

	public GSM0348PoRCertificateMode getPoRCertificateMode()
	{
		return GSM0348PoRCertificateMode.get((byte) ((m_data & 0xC) >> 2));
	}

	public GSM0348PoRProtocol getPoRProtocol()
	{
		return GSM0348PoRProtocol.get((byte) ((m_data & 0x20) >> 5));
	}

	public GSM0348PoRMode getPoRMode()
	{
		return GSM0348PoRMode.get((byte) (m_data & 0x3));
	}

	public boolean isPoRCiphered()
	{
		return ((m_data & 0x10) != 0);
	}

	public String toString()
	{
		return "ResponseSPI[PoRCertificateMode=" + getPoRCertificateMode() + ", PoRProtocol=" + getPoRProtocol() + ", PoRMode="
				+ getPoRMode() + ", PoRCiphered=" + isPoRCiphered() + ", raw=" + Util.toHex(m_data) + "]";
	}

	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof ResponseSPIImpl))
			return false;
		ResponseSPIImpl rspii = (ResponseSPIImpl) obj;
		return m_data == rspii.m_data;
	}

	public int hashCode()
	{
		int result = 42;
		result = 37 * result + m_data;
		return result;
	}
}
