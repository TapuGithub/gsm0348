package ru.tapublog.lib.gsm0348.impl;

import java.util.Arrays;

import ru.tapublog.lib.gsm0348.api.PacketBuilderConfiguration;
import ru.tapublog.lib.gsm0348.api.SecurityBytesType;

/**
 * {@linkplain PacketBuilderConfiguration} implementation.
 * 
 * @author Victor Platov
 */
public class PacketBuilderConfigurationImpl implements PacketBuilderConfiguration
{
	private byte m_kic;
	private byte m_kid;
	private byte[] m_tar;
	private byte[] m_spi;

	private String m_signatureAlgorithm;
	private String m_cihperingAlgorithm;

	private SecurityBytesType m_securityBytesType = SecurityBytesType.WITH_LENGHTS_AND_UDHL;

	public PacketBuilderConfigurationImpl()
	{
		m_tar = new byte[0];
		m_spi = new byte[0];
	}

	public PacketBuilderConfigurationImpl(PacketBuilderConfiguration copy)
	{
		setKIc(copy.getKIc());
		setKID(copy.getKID());
		setTAR(copy.getTAR());
		setSPI(copy.getSPI());
		setSignatureAlgorithm(copy.getSignatureAlgorithm());
		setCipheringAlgorithm(copy.getCipheringAlgorithm());
		setSecurityBytesType(copy.getSecurityBytesType());
	}

	@Override
	public byte getKIc()
	{
		return m_kic;
	}

	@Override
	public void setKIc(byte kic)
	{
		m_kic = kic;
	}

	@Override
	public byte getKID()
	{
		return m_kid;
	}

	@Override
	public void setKID(byte kid)
	{
		m_kid = kid;
	}

	@Override
	public byte[] getTAR()
	{
		return m_tar.clone();
	}

	@Override
	public void setTAR(byte[] tar) throws IllegalArgumentException
	{
		if (tar.length != 3)
			throw new IllegalArgumentException("TAR length must be 3. Current length = " + tar.length + " value="
					+ Util.toHexArray(tar));
		m_tar = tar.clone();
	}

	@Override
	public byte[] getSPI()
	{
		return m_spi.clone();
	}

	@Override
	public void setSPI(byte[] spi) throws IllegalArgumentException
	{
		if (spi.length != 2)
			throw new IllegalArgumentException("SPI length must be 2. Current length = " + spi.length + " value="
					+ Util.toHexArray(spi));
		m_spi = spi.clone();
	}

	@Override
	public String getSignatureAlgorithm()
	{
		return m_signatureAlgorithm;
	}

	@Override
	public void setSignatureAlgorithm(String name)
	{
		m_signatureAlgorithm = name;
	}

	@Override
	public String getCipheringAlgorithm()
	{
		return m_cihperingAlgorithm;
	}

	@Override
	public void setCipheringAlgorithm(String name)
	{
		m_cihperingAlgorithm = name;
	}

	public String toString()
	{
		return "CommandBuilderConfigurationImpl[KIc=" + Util.toHex(m_kic) + ", KID=" + Util.toHex(m_kid) + ", TAR=["
				+ Util.toHexArray(m_tar) + "], SPI=[" + Util.toHexArray(m_spi) + "], cipheringAlgorithm=" + m_cihperingAlgorithm
				+ ", signatureAlgorithm=" + m_signatureAlgorithm + ", securityBytesType=" + m_securityBytesType + "]";
	}

	@Override
	public SecurityBytesType getSecurityBytesType()
	{
		return m_securityBytesType;
	}

	@Override
	public int hashCode()
	{
		final int prime = 31;
		int result = 1;
		result = prime * result + ((m_cihperingAlgorithm == null) ? 0 : m_cihperingAlgorithm.hashCode());
		result = prime * result + m_kic;
		result = prime * result + m_kid;
		result = prime * result + ((m_signatureAlgorithm == null) ? 0 : m_signatureAlgorithm.hashCode());
		result = prime * result + Arrays.hashCode(m_spi);
		result = prime * result + Arrays.hashCode(m_tar);
		return result;
	}

	@Override
	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof PacketBuilderConfigurationImpl))
			return false;
		PacketBuilderConfigurationImpl other = (PacketBuilderConfigurationImpl) obj;
		if (m_cihperingAlgorithm == null)
		{
			if (other.m_cihperingAlgorithm != null)
				return false;
		} else if (!m_cihperingAlgorithm.equals(other.m_cihperingAlgorithm))
			return false;
		if (m_kic != other.m_kic)
			return false;
		if (m_kid != other.m_kid)
			return false;
		if (m_signatureAlgorithm == null)
		{
			if (other.m_signatureAlgorithm != null)
				return false;
		} else if (!m_signatureAlgorithm.equals(other.m_signatureAlgorithm))
			return false;
		if (!Arrays.equals(m_spi, other.m_spi))
			return false;
		if (!Arrays.equals(m_tar, other.m_tar))
			return false;
		return true;
	}

	@Override
	public void setSecurityBytesType(SecurityBytesType securityBytesType)
	{
		m_securityBytesType = securityBytesType;
	}
}
