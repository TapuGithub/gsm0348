package ru.tapublog.lib.gsm0348.impl;

import ru.tapublog.lib.gsm0348.impl.Util;
import ru.tapublog.lib.gsm0348.api.PacketBuilderConfiguration;

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
	}

	public byte getKIc()
	{
		return m_kic;
	}

	public void setKIc(byte kic)
	{
		m_kic = kic;
	}

	public byte getKID()
	{
		return m_kid;
	}

	public void setKID(byte kid)
	{
		m_kid = kid;
	}

	public byte[] getTAR()
	{
		return m_tar.clone();
	}

	public void setTAR(byte[] tar) throws IllegalArgumentException
	{
		if (tar.length != 3)
			throw new IllegalArgumentException("TAR length must be 3. Current length = " + tar.length + " value="
					+ Util.toHexArray(tar));
		m_tar = tar.clone();
	}

	public byte[] getSPI()
	{
		return m_spi.clone();
	}

	public void setSPI(byte[] spi) throws IllegalArgumentException
	{
		if (spi.length != 2)
			throw new IllegalArgumentException("SPI length must be 3. Current length = " + spi.length + " value="
					+ Util.toHexArray(spi));
		m_spi = spi.clone();
	}

	public String getSignatureAlgorithm()
	{
		return m_signatureAlgorithm;
	}

	public void setSignatureAlgorithm(String name)
	{
		m_signatureAlgorithm = name;
	}

	public String getCipheringAlgorithm()
	{
		return m_cihperingAlgorithm;
	}

	public void setCipheringAlgorithm(String name)
	{
		m_cihperingAlgorithm = name;
	}

	public String toString()
	{
		return "CommandBuilderConfigurationImpl[KIc=" + Util.toHex(m_kic) + ", KID=" + Util.toHex(m_kid) + ", TAR=["
				+ Util.toHexArray(m_tar) + "], SPI=[" + Util.toHexArray(m_spi) + "], cipheringAlgorithm=" + m_cihperingAlgorithm
				+ ", signatureAlgorithm=" + m_signatureAlgorithm + "]";
	}

	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof PacketBuilderConfigurationImpl))
			return false;
		PacketBuilderConfigurationImpl pbci = (PacketBuilderConfigurationImpl) obj;
		if (m_tar.length != pbci.m_tar.length)
			return false;
		for (int i = 0; i < m_tar.length; i++)
			if (m_tar[i] != pbci.m_tar[i])
				return false;
		if (m_spi.length != pbci.m_spi.length)
			return false;
		for (int i = 0; i < m_spi.length; i++)
			if (m_spi[i] != pbci.m_spi[i])
				return false;
		return m_kic == pbci.m_kic
				&& m_kid == pbci.m_kid
				&& (m_signatureAlgorithm == null ? pbci.m_signatureAlgorithm == null : m_signatureAlgorithm
						.equals(pbci.m_signatureAlgorithm))
				&& (m_cihperingAlgorithm == null ? pbci.m_cihperingAlgorithm == null : m_cihperingAlgorithm
						.equals(pbci.m_cihperingAlgorithm));
	}

	public int hashCode()
	{
		int result = 42;
		result = 37 * result + m_kic;
		result = 37 * result + m_kid;

		for (int i = 0; i < m_tar.length; i++)
			result = 37 * result + m_tar[i];
		for (int i = 0; i < m_spi.length; i++)
			result = 37 * result + m_spi[i];

		result = 37 * result + (m_cihperingAlgorithm == null ? 0 : m_cihperingAlgorithm.hashCode());
		result = 37 * result + (m_signatureAlgorithm == null ? 0 : m_signatureAlgorithm.hashCode());
		return result;
	}
}
