package ru.tapublog.lib.gsm0348.impl;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import ru.tapublog.lib.gsm0348.api.CommandPacket;
import ru.tapublog.lib.gsm0348.api.CommandPacketHeader;
import ru.tapublog.lib.gsm0348.api.Gsm0348Exception;
import ru.tapublog.lib.gsm0348.api.PacketBuilder;
import ru.tapublog.lib.gsm0348.api.PacketBuilderConfiguration;
import ru.tapublog.lib.gsm0348.api.PacketBuilderConfigurationException;
import ru.tapublog.lib.gsm0348.api.ResponsePacket;
import ru.tapublog.lib.gsm0348.api.ResponsePacketHeader;
import ru.tapublog.lib.gsm0348.api.SecurityBytesType;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.CommandSPI;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.KID;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.KIc;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.ResponseSPI;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.certificate.GSM0348CertificateMode;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.response.GSM0348PoRCertificateMode;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.synchronization.GSM0348SynchroCounterMode;
import ru.tapublog.lib.gsm0348.api.header.responsepacket.GSM0348ResponsePacketStatusCode;
import ru.tapublog.lib.gsm0348.impl.crypto.CipheringManager;
import ru.tapublog.lib.gsm0348.impl.crypto.SignatureManager;

/**
 * This utility class is used for ciphering operations during GSM 03.48 packet
 * creation and recovering.
 * 
 * @author Victor Platov
 */
@NotThreadSafe
public class PacketBuilderImpl implements PacketBuilder
{
	private static final Logger LOGGER = Logger.getLogger(PacketBuilderImpl.class);

	private PacketBuilderConfiguration m_builderConfig;

	private boolean m_commandPacketCiphering;
	private boolean m_commandPacketSigning;

	private boolean m_responsePacketCiphering;
	private boolean m_responsePacketSigning;

	private boolean m_usingCounters;

	private static final int PACKET_LENGHT_SIZE = 2;

	private static final int HEADER_LENGHT_POSITION = 0;
	private static final int HEADER_LENGHT_RESPONSE_POSITION = 2;
	private static final int HEADER_LENGHT_SIZE = 1;

	private static final int SPI_POSITION = 1;
	private static final int SPI_SIZE = 2;

	private static final int KIC_POSITION = 3;
	private static final int KIC_SIZE = 1;

	private static final int KID_POSITION = 4;
	private static final int KID_SIZE = 1;

	private static final int TAR_POSITION = 5;
	private static final int TAR_RESPONSE_POSITION = 3;
	private static final int TAR_SIZE = 3;

	private static final int COUNTERS_POSITION = 8;
	private static final int COUNTERS_RESPONSE_POSITION = 6;
	private static final int COUNTERS_SIZE = 5;

	private static final int PADDING_COUNTER_POSITION = 13;
	private static final int PADDING_COUNTER_RESPONSE_POSITION = 11;
	private static final int PADDING_COUNTER_SIZE = 1;

	private static final int RESPONSE_CODE_RESPONSE_POSITION = 12;
	private static final int RESPONSE_CODE_RESPONSE_SIZE = 1;

	private static final int SIGNATURE_POSITION = 14;
	private static final int SIGNATURE_RESPONSE_POSITION = 13;

	private static final int MINIMUM_RESPONSE_PACKET_SIZE = 13;

	private static final int HEADER_SIZE_WITOUT_SIGNATURE = SPI_SIZE + KIC_SIZE + KID_SIZE + TAR_SIZE + COUNTERS_SIZE
			+ PADDING_COUNTER_SIZE;

	private String m_cipheringAlgorithmName;
	private String m_signatureAlgorithmName;
	private int m_cipherBlockSize;
	private int m_signatureSize;

	PacketBuilderImpl()
	{

	}

	PacketBuilderImpl(PacketBuilderConfiguration parameters) throws PacketBuilderConfigurationException
	{
		setConfiguration(parameters);
	}

	private void setCipheringAlgorithmName(PacketBuilderConfiguration builderConfiguration)
			throws PacketBuilderConfigurationException
	{
		final KIc kic = new KIcImpl(builderConfiguration.getKIc());
		switch (kic.getAlgorithmImplementation())
		{
			case RESERVED:
				throw new PacketBuilderConfigurationException("Using reserved value for algorithm implementation in KIc");

			case PROPRIETARY_IMPLEMENTATIONS:
			case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
				m_cipheringAlgorithmName = builderConfiguration.getCipheringAlgorithm();
				if (m_cipheringAlgorithmName == null || m_cipheringAlgorithmName.isEmpty())
					throw new PacketBuilderConfigurationException(
							"In selected configuration ciphering algorithm name cannot be null or empty");
				break;
			case DES:
				switch (kic.getCipheringAlgorithmMode())
				{
					case DES_CBC:
						m_cipheringAlgorithmName = "DES/CBC/ZeroBytePadding";
						break;

					case DES_ECB:
						m_cipheringAlgorithmName = "DES/ECB/ZeroBytePadding";
						break;

					case TRIPLE_DES_CBC_2_KEYS:
					case TRIPLE_DES_CBC_3_KEYS:
						m_cipheringAlgorithmName = "DESede/CBC/ZeroBytePadding";
						break;

					default:
						throw new PacketBuilderConfigurationException("Not implemented yet");
				}
				break;
			default:
				throw new PacketBuilderConfigurationException("Not implemented yet");
		}
		try
		{
			m_cipherBlockSize = CipheringManager.getBlockSize(m_cipheringAlgorithmName);
		}
		catch (NoSuchAlgorithmException ex)
		{
			throw new PacketBuilderConfigurationException(ex);
		}
		catch (NoSuchPaddingException ex)
		{
			throw new PacketBuilderConfigurationException(ex);
		}
	}

	private void setSigningAlgorithmName(PacketBuilderConfiguration builderConfiguration)
			throws PacketBuilderConfigurationException
	{
		final KID kid = new KIDImpl(builderConfiguration.getKID());
		switch (kid.getAlgorithmImplementation())
		{
			case RESERVED:
				throw new PacketBuilderConfigurationException("Using reserved value for algorithm implementation in KID");

			case PROPRIETARY_IMPLEMENTATIONS:
			case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
				m_signatureAlgorithmName = builderConfiguration.getSignatureAlgorithm();
				if (m_signatureAlgorithmName == null || m_signatureAlgorithmName.isEmpty())
					throw new PacketBuilderConfigurationException(
							"In selected configuration signature algorithm name cannot be null or empty");
				break;
			case DES:
				switch (kid.getCertificateAlgorithmMode())
				{
					case DES_CBC:
						m_signatureAlgorithmName = SignatureManager.DES_MAC8_ISO9797_M1;
						break;

					case RESERVED:
						throw new PacketBuilderConfigurationException("Using reserved value for algorithm mode in KID");

					case TRIPLE_DES_CBC_2_KEYS:
					case TRIPLE_DES_CBC_3_KEYS:
						m_signatureAlgorithmName = "DESEDEMAC64";
						break;

					default:
						throw new PacketBuilderConfigurationException("Not implemented yet");
				}
				break;
			default:
				throw new PacketBuilderConfigurationException("Not implemented yet");
		}
		try
		{
			m_signatureSize = SignatureManager.signLength(m_signatureAlgorithmName);
		}
		catch (NoSuchAlgorithmException ex)
		{
			throw new PacketBuilderConfigurationException(ex);
		}
	}

	@Override
	public CommandPacket buildCommandPacket(byte[] data, byte[] counters, byte[] cipheringKey, byte[] signatureKey)
			throws PacketBuilderConfigurationException, Gsm0348Exception
	{
		if (!isConfigured())
			throw new PacketBuilderConfigurationException("Not configured");

		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Creating command packet.\n\tData:" + Util.toHexArray(data) + "\n\tCounters:"
					+ Util.toHexArray(counters) + "\n\tCipheringKey:" + Util.toHexArray(cipheringKey) + "\n\tSigningKey:"
					+ Util.toHexArray(signatureKey));

		if (m_commandPacketCiphering && (cipheringKey == null))
			throw new PacketBuilderConfigurationException("Ciphering is enabled - ciphering key must be specified");
		if (m_commandPacketSigning && (signatureKey == null))
			throw new PacketBuilderConfigurationException("Signing is enabled - signature key must be specified");
		if (counters == null && m_usingCounters)
			throw new PacketBuilderConfigurationException("Counters are null and they are required by configuration");
		if (counters != null && counters.length != COUNTERS_SIZE)
			throw new PacketBuilderConfigurationException("Counters size mismatch. Current = "
					+ (counters != null ? counters.length : "counter == null") + ". Required:" + COUNTERS_SIZE);

		try
		{
			final int signatureLength = m_commandPacketSigning ? m_signatureSize : 0;
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Signature length: " + signatureLength);
			final int headerLenght = HEADER_SIZE_WITOUT_SIGNATURE + HEADER_LENGHT_SIZE + signatureLength;
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Header length(including size byte): " + headerLenght);

			byte[] signature = new byte[signatureLength];
			byte[] headerData = new byte[headerLenght];
			byte[] dataBytes = (data == null) ? new byte[0] : data;
			byte[] countersBytes = m_usingCounters ? counters : new byte[COUNTERS_SIZE];
			byte paddingCounter = 0;

			headerData[HEADER_LENGHT_POSITION] = (byte) (headerLenght - HEADER_LENGHT_SIZE);
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Header length value: " + headerData[HEADER_LENGHT_POSITION]);
			System.arraycopy(m_builderConfig.getSPI(), 0, headerData, SPI_POSITION, SPI_SIZE);
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("SPI value: "
						+ Util.toHexArray(Arrays.copyOfRange(headerData, SPI_POSITION, SPI_POSITION + SPI_SIZE)));
			headerData[KIC_POSITION] = m_builderConfig.getKIc();
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("KIc value: " + Util.toHex(headerData[KIC_POSITION]));
			headerData[KID_POSITION] = m_builderConfig.getKID();
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("KID value: " + Util.toHex(headerData[KID_POSITION]));
			System.arraycopy(m_builderConfig.getTAR(), 0, headerData, TAR_POSITION, TAR_SIZE);
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("TAR value: "
						+ Util.toHexArray(Arrays.copyOfRange(headerData, TAR_POSITION, TAR_POSITION + TAR_SIZE)));
			System.arraycopy(countersBytes, 0, headerData, COUNTERS_POSITION, COUNTERS_SIZE);
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("COUNTERS value: "
						+ Util.toHexArray(Arrays.copyOfRange(headerData, COUNTERS_POSITION, COUNTERS_POSITION + COUNTERS_SIZE)));

			if (m_commandPacketCiphering)
			{
				final int dataSize = COUNTERS_SIZE + PADDING_COUNTER_SIZE + signatureLength + dataBytes.length;
				int remainder = dataSize % m_cipherBlockSize;
				if (remainder != 0)
					paddingCounter = (byte) (m_cipherBlockSize - remainder);

			}
			headerData[PADDING_COUNTER_POSITION] = paddingCounter;

			if (LOGGER.isDebugEnabled())
				LOGGER.debug(String.format("Padding counter value:%X", headerData[PADDING_COUNTER_POSITION]));

			if (m_commandPacketSigning)
			{
				if (LOGGER.isDebugEnabled())
					LOGGER.debug("Signing");
				byte[] signData = new byte[headerLenght + dataBytes.length - signatureLength + PACKET_LENGHT_SIZE
						+ paddingCounter];
				if (LOGGER.isDebugEnabled())
					LOGGER.debug("Signing data length: " + signData.length);
				final int length = dataBytes.length + paddingCounter + headerLenght;
				signData[0] = (byte) ((length & 0xFF) >> 8);
				signData[1] = (byte) ((length & 0xFF));
				System.arraycopy(headerData, 0, signData, 2, headerLenght - signatureLength);
				System.arraycopy(dataBytes, 0, signData, headerLenght - signatureLength + 2, dataBytes.length);
				if (LOGGER.isDebugEnabled())
					LOGGER.debug("Signing data : " + Util.toHexArray(signData));
				signature = SignatureManager.sing(m_signatureAlgorithmName, signatureKey, signData);
			}
			System.arraycopy(signature, 0, headerData, SIGNATURE_POSITION, signatureLength);

			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Signature value: " + Util.toHexArray(signature));

			if (m_commandPacketCiphering)
			{
				if (LOGGER.isDebugEnabled())
					LOGGER.debug("Ciphering");
				byte[] cipherData = new byte[COUNTERS_SIZE + PADDING_COUNTER_SIZE + signatureLength + dataBytes.length];
				if (LOGGER.isDebugEnabled())
					LOGGER.debug("Ciphering data length: " + cipherData.length);
				System.arraycopy(countersBytes, 0, cipherData, 0, COUNTERS_SIZE);
				cipherData[5] = paddingCounter;
				System.arraycopy(signature, 0, cipherData, 6, signatureLength);
				System.arraycopy(dataBytes, 0, cipherData, 6 + signatureLength, dataBytes.length);
				dataBytes = new byte[dataBytes.length + paddingCounter];

				byte[] cipheredData = CipheringManager
						.encipher(m_cipheringAlgorithmName, cipheringKey, cipherData, countersBytes);
				if (LOGGER.isDebugEnabled())
					LOGGER.debug("Ciphered data length: " + cipheredData.length);
				System.arraycopy(cipheredData, 0, countersBytes, 0, COUNTERS_SIZE);
				System.arraycopy(cipheredData, 6, signature, 0, signatureLength);
				System.arraycopy(cipheredData, 6 + signatureLength, dataBytes, 0, dataBytes.length);
				paddingCounter = cipheredData[5];

				headerData[PADDING_COUNTER_POSITION] = paddingCounter;
				System.arraycopy(signature, 0, headerData, SIGNATURE_POSITION, signatureLength);
				System.arraycopy(countersBytes, 0, headerData, COUNTERS_POSITION, COUNTERS_SIZE);
			}
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Header raw data : " + Util.toHexArray(headerData));
			CommandPacketHeader header = new CommandPacketHeaderImpl(headerData, signatureLength);
			CommandPacket packet = new CommandPacketImpl(header, new PacketDataImpl(dataBytes));
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Packet created : " + packet);
			return packet;
		}
		catch (GeneralSecurityException e)
		{
			throw new Gsm0348Exception(e);
		}
	}

	@Override
	public ResponsePacket recoverResponsePacket(byte[] rawdata, byte[] cipheringKey, byte[] signatureKey)
			throws PacketBuilderConfigurationException, Gsm0348Exception
	{
		if (!isConfigured())
			throw new PacketBuilderConfigurationException("Not configured");

		if (rawdata == null)
			throw new NullPointerException("packet data cannot be null");

		if (m_responsePacketCiphering && (cipheringKey == null))
			throw new PacketBuilderConfigurationException("Response ciphering is enabled - ciphering key must be specified");
		if (m_responsePacketSigning && (signatureKey == null))
			throw new PacketBuilderConfigurationException("Response signing is enabled - signature key must be specified");

		final int packetLength = Util.unsignedByteToInt(rawdata[0]) + Util.unsignedByteToInt(rawdata[1]);
		if (rawdata.length - PACKET_LENGHT_SIZE != packetLength)
			throw new Gsm0348Exception("Length of raw data doesnt match packet length. Expected " + packetLength + " but found "
					+ (rawdata.length - PACKET_LENGHT_SIZE));

		final int headerLength = Util.unsignedByteToInt(rawdata[HEADER_LENGHT_RESPONSE_POSITION]);
		final byte[] tar = new byte[TAR_SIZE];
		System.arraycopy(rawdata, TAR_RESPONSE_POSITION, tar, 0, TAR_SIZE);
		final byte[] counters = new byte[COUNTERS_SIZE];
		final int signatureLength = m_responsePacketSigning ? m_signatureSize : 0;

		if (rawdata.length < MINIMUM_RESPONSE_PACKET_SIZE + signatureLength)
		{
			String message = "rawdata too small to be response packet. Expected to be not less then "
					+ (MINIMUM_RESPONSE_PACKET_SIZE) + ", but found " + rawdata.length;
			if (rawdata.length < MINIMUM_RESPONSE_PACKET_SIZE)
			{
				message += ". It can be caused by incorrect profile(SPI value). Check SPI!";
				if (LOGGER.isEnabledFor(Level.WARN))
					LOGGER.warn("Packet recived(raw): " + Arrays.toString(rawdata));
			}
			throw new Gsm0348Exception(message);
		}

		final byte[] signature = new byte[signatureLength];
		int paddingCounter = Util.unsignedByteToInt(rawdata[PADDING_COUNTER_RESPONSE_POSITION]);
		if (!m_responsePacketCiphering && paddingCounter != 0)
			throw new Gsm0348Exception(
					"Response packet ciphering is off but padding counter isnot 0. So it can be corrupted packet or configuration doesn`t match provided data");
		byte responseCode = 0;
		byte[] data;
		try
		{
			if (m_responsePacketCiphering)
			{
				byte[] dataEnc = CipheringManager.decipher(m_cipheringAlgorithmName, cipheringKey,
						Arrays.copyOfRange(rawdata, 6, rawdata.length - 1));
				System.arraycopy(dataEnc, 0, counters, 0, COUNTERS_SIZE);
				paddingCounter = Util.unsignedByteToInt(dataEnc[COUNTERS_SIZE]);
				responseCode = dataEnc[COUNTERS_SIZE + 1];
				System.arraycopy(dataEnc, COUNTERS_SIZE + 2, signature, 0, signatureLength);
				final int dataSize = dataEnc.length - TAR_SIZE - HEADER_LENGHT_SIZE;
				data = new byte[dataSize];
				System.arraycopy(dataEnc, COUNTERS_SIZE + 2 + signatureLength, data, 0, dataSize);
			}
			else
			{
				System.arraycopy(rawdata, COUNTERS_RESPONSE_POSITION, counters, 0, COUNTERS_SIZE);
				paddingCounter = Util.unsignedByteToInt(rawdata[PADDING_COUNTER_RESPONSE_POSITION]);
				responseCode = rawdata[RESPONSE_CODE_RESPONSE_POSITION];
				System.arraycopy(rawdata, SIGNATURE_RESPONSE_POSITION, signature, 0, signatureLength);
				final int dataSize = packetLength - headerLength - HEADER_LENGHT_SIZE;
				data = new byte[dataSize];
				System.arraycopy(rawdata, headerLength + HEADER_LENGHT_SIZE + PACKET_LENGHT_SIZE, data, 0, dataSize);
			}

			if (m_responsePacketSigning)
			{
				int addonAmount = 0;
				if (m_builderConfig.getSecurityBytesType() == SecurityBytesType.WITH_LENGHTS_AND_UDHL)
					addonAmount = 6;
				else if (m_builderConfig.getSecurityBytesType() == SecurityBytesType.WITH_LENGHTS)
					addonAmount = 3;

				byte[] signData = new byte[addonAmount + TAR_SIZE + PADDING_COUNTER_SIZE + RESPONSE_CODE_RESPONSE_SIZE
						+ COUNTERS_SIZE + data.length];
				switch (m_builderConfig.getSecurityBytesType())
				{
					case WITH_LENGHTS_AND_UDHL:
						signData[0] = 0x02;
						signData[1] = 0x71;
						signData[2] = 0x00;
						System.arraycopy(rawdata, 0, signData, 3, 3);
						break;
					case WITH_LENGHTS:
						System.arraycopy(rawdata, 0, signData, 0, 3);
						break;
				}

				System.arraycopy(tar, 0, signData, addonAmount, TAR_SIZE);
				System.arraycopy(counters, 0, signData, addonAmount + TAR_SIZE, COUNTERS_SIZE);
				signData[addonAmount + TAR_SIZE + COUNTERS_SIZE] = (byte) paddingCounter;
				signData[addonAmount + TAR_SIZE + COUNTERS_SIZE + 1] = responseCode;
				System.arraycopy(data, 0, signData, addonAmount + TAR_SIZE + COUNTERS_SIZE + 2, data.length);

				boolean valid = SignatureManager.verify(m_signatureAlgorithmName, signatureKey, signData, signature);
				if (!valid)
					throw new Gsm0348Exception("Signatures doesnt match");
			}

			final byte[] headerData = new byte[headerLength + HEADER_LENGHT_SIZE];
			headerData[0] = (byte) headerLength;
			System.arraycopy(tar, 0, headerData, 1, TAR_SIZE);
			System.arraycopy(counters, 0, headerData, 1 + TAR_SIZE, COUNTERS_SIZE);
			headerData[PADDING_COUNTER_SIZE + TAR_SIZE + COUNTERS_SIZE] = (byte) paddingCounter;
			headerData[PADDING_COUNTER_SIZE + TAR_SIZE + COUNTERS_SIZE + RESPONSE_CODE_RESPONSE_SIZE] = (byte) responseCode;
			System.arraycopy(signature, 0, headerData, PADDING_COUNTER_SIZE + TAR_SIZE + COUNTERS_SIZE
					+ RESPONSE_CODE_RESPONSE_SIZE + 1, signatureLength);

			ResponsePacketHeader header = new ResponsePacketHeaderImpl(headerData, signatureLength);
			ResponsePacket packet = new ResponsePacketImpl(header, new PacketDataImpl(data));
			return packet;
		}
		catch (GeneralSecurityException e)
		{
			throw new Gsm0348Exception(e);
		}
	}

	@Override
	@Deprecated
	public ResponsePacket buildResponsePacket(byte[] data, byte[] counters, byte[] cipheringKey, byte[] signatureKey,
			GSM0348ResponsePacketStatusCode responseCode) throws PacketBuilderConfigurationException, Gsm0348Exception
	{
		throw new IllegalArgumentException("Not implemented yet");
	}

	@Override
	public void setConfiguration(PacketBuilderConfiguration builderConfiguration) throws PacketBuilderConfigurationException
	{
		if (builderConfiguration.getTAR() == null || builderConfiguration.getTAR().length != 3)
			throw new PacketBuilderConfigurationException("TAR value null or not a 3 bytes arays");

		if (builderConfiguration.getSPI() == null || builderConfiguration.getSPI().length != 2)
			throw new PacketBuilderConfigurationException("SPI value null or not a 2 bytes arays");

		final CommandSPI commandSPI = new CommandSPIImpl(builderConfiguration.getSPI()[0]);
		final ResponseSPI responseSPI = new ResponseSPIImpl(builderConfiguration.getSPI()[1]);

		m_commandPacketCiphering = commandSPI.isCiphered();
		m_responsePacketCiphering = responseSPI.isPoRCiphered();

		if (m_commandPacketCiphering || m_responsePacketCiphering)
			setCipheringAlgorithmName(builderConfiguration);

		m_commandPacketSigning = commandSPI.getCertificateMode() != GSM0348CertificateMode.NO_SECURITY;
		m_responsePacketSigning = responseSPI.getPoRCertificateMode() != GSM0348PoRCertificateMode.NO_SECURITY;

		if (m_commandPacketSigning || m_responsePacketSigning)
			setSigningAlgorithmName(builderConfiguration);

		m_usingCounters = commandSPI.getSynchroCounterMode() != GSM0348SynchroCounterMode.NO_COUNTER;
		if (LOGGER.isDebugEnabled() && !m_usingCounters)
			LOGGER.debug("Counters are turned off - counters field in CommandPacked will be filled with zeroes");
		m_builderConfig = new PacketBuilderConfigurationImpl(builderConfiguration);
	}

	@Override
	public PacketBuilderConfiguration getConfiguration()
	{
		return m_builderConfig;
	}

	@Override
	public boolean isConfigured()
	{
		return m_builderConfig != null;
	}

	@Override
	@Deprecated
	public CommandPacket recoverCommandPacket(byte[] data, byte[] cipheringKey, byte[] signatureKey)
			throws PacketBuilderConfigurationException, Gsm0348Exception
	{
		throw new IllegalArgumentException("Not implemented yet");
	}
}
