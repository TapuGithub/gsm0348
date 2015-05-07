package ru.tapublog.lib.gsm0348.impl;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import ru.tapublog.lib.gsm0348.api.Gsm0348Exception;
import ru.tapublog.lib.gsm0348.api.PacketBuilder;
import ru.tapublog.lib.gsm0348.api.PacketBuilderConfigurationException;
import ru.tapublog.lib.gsm0348.api.model.CardProfile;
import ru.tapublog.lib.gsm0348.api.model.CertificationMode;
import ru.tapublog.lib.gsm0348.api.model.CommandPacket;
import ru.tapublog.lib.gsm0348.api.model.CommandSPI;
import ru.tapublog.lib.gsm0348.api.model.KIC;
import ru.tapublog.lib.gsm0348.api.model.KID;
import ru.tapublog.lib.gsm0348.api.model.ResponsePacket;
import ru.tapublog.lib.gsm0348.api.model.ResponsePacketHeader;
import ru.tapublog.lib.gsm0348.api.model.ResponsePacketStatus;
import ru.tapublog.lib.gsm0348.api.model.ResponseSPI;
import ru.tapublog.lib.gsm0348.api.model.SecurityBytesType;
import ru.tapublog.lib.gsm0348.api.model.SynchroCounterMode;
import ru.tapublog.lib.gsm0348.impl.coders.CommandSPICoder;
import ru.tapublog.lib.gsm0348.impl.coders.KICCoder;
import ru.tapublog.lib.gsm0348.impl.coders.KIDCoder;
import ru.tapublog.lib.gsm0348.impl.coders.ResponsePacketStatusCoder;
import ru.tapublog.lib.gsm0348.impl.coders.ResponseSPICoder;
import ru.tapublog.lib.gsm0348.impl.crypto.CipheringManager;
import ru.tapublog.lib.gsm0348.impl.crypto.SignatureManager;

public class PacketBuilderImpl implements PacketBuilder
{
	private static final Logger LOGGER = Logger.getLogger(PacketBuilderImpl.class);

	private boolean commandPacketCiphering;
	private boolean commandPacketSigning;

	private boolean responsePacketCiphering;
	private boolean responsePacketSigning;

	private boolean usingCounters;

	private CardProfile cardProfile;

	private String cipheringAlgorithmName;
	private String signatureAlgorithmName;

	private int cipherBlockSize;
	private int signatureSize;

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

	public PacketBuilderImpl()
	{

	}

	public PacketBuilderImpl(CardProfile cardProfile) throws PacketBuilderConfigurationException
	{
		setProfile(cardProfile);
	}

	private CardProfile copyProfile(CardProfile profile) throws Gsm0348Exception
	{
		try
		{
			return (CardProfile) BeanUtils.cloneBean(profile);
		}
		catch (Exception ex)
		{
			throw new Gsm0348Exception(ex);
		}
	}

	private void verifyProfile(CardProfile cardProfile) throws PacketBuilderConfigurationException
	{
		if (cardProfile == null)
			throw new PacketBuilderConfigurationException("profile cannot be null");

		if (cardProfile.getKIC() == null)
			throw new PacketBuilderConfigurationException("KIC cannot be null");
		if (cardProfile.getKIC().getAlgorithmImplementation() == null)
			throw new PacketBuilderConfigurationException("KIC AlgorithmImplementation cannot be null");
		if (cardProfile.getKIC().getCipheringAlgorithmMode() == null)
			throw new PacketBuilderConfigurationException("KIC CipheringAlgorithmMode cannot be null");
		if (cardProfile.getKIC().getKeysetID() < 0x0 || cardProfile.getKIC().getKeysetID() > 0xF)
			throw new PacketBuilderConfigurationException("KIC keySetID cannot be <0 and >15");

		if (cardProfile.getKID() == null)
			throw new PacketBuilderConfigurationException("KID cannot be null");
		if (cardProfile.getKID().getAlgorithmImplementation() == null)
			throw new PacketBuilderConfigurationException("KID AlgorithmImplementation cannot be null");
		if (cardProfile.getKID().getCertificationAlgorithmMode() == null)
			throw new PacketBuilderConfigurationException("KID CertificationAlgorithmMode cannot be null");
		if (cardProfile.getKID().getKeysetID() < 0x0 || cardProfile.getKID().getKeysetID() > 0xF)
			throw new PacketBuilderConfigurationException("KID keySetID cannot be <0 and >15");

		if (cardProfile.getSPI() == null)
			throw new PacketBuilderConfigurationException("SPI cannot be null");

		if (cardProfile.getSPI().getCommandSPI() == null)
			throw new PacketBuilderConfigurationException("CommandSPI cannot be null");
		if (cardProfile.getSPI().getCommandSPI().getCertificationMode() == null)
			throw new PacketBuilderConfigurationException("CommandSPI CertificationMode cannot be null");
		if (cardProfile.getSPI().getCommandSPI().getSynchroCounterMode() == null)
			throw new PacketBuilderConfigurationException("CommandSPI SynchroCounterMode cannot be null");

		if (cardProfile.getSPI().getResponseSPI() == null)
			throw new PacketBuilderConfigurationException("ResponseSPI cannot be null");
		if (cardProfile.getSPI().getResponseSPI().getPoRCertificateMode() == null)
			throw new PacketBuilderConfigurationException("ResponseSPI PoRCertificateMode cannot be null");
		if (cardProfile.getSPI().getResponseSPI().getPoRMode() == null)
			throw new PacketBuilderConfigurationException("ResponseSPI PoRMode cannot be null");
		if (cardProfile.getSPI().getResponseSPI().getPoRProtocol() == null)
			throw new PacketBuilderConfigurationException("ResponseSPI PoRProtocol cannot be null");

		if (cardProfile.getSecurityBytesType() == null)
			throw new PacketBuilderConfigurationException("SecurityBytesType cannot be null");

		if (cardProfile.getTAR() == null || cardProfile.getTAR().length != 3)
			throw new PacketBuilderConfigurationException("TAR value null or not a 3 bytes arays");
	}

	@Override
	public void setProfile(CardProfile cardProfile) throws PacketBuilderConfigurationException
	{
		verifyProfile(cardProfile);

		CommandSPI commandSPI = cardProfile.getSPI().getCommandSPI();
		ResponseSPI responseSPI = cardProfile.getSPI().getResponseSPI();

		if (commandSPI.getCertificationMode() == CertificationMode.DS)
			throw new PacketBuilderConfigurationException("Digital signature in command packets is not supported");
		if (commandSPI.getCertificationMode() == CertificationMode.RC)
			throw new PacketBuilderConfigurationException("Redundancy checking in command packets is not supported");
		if (responseSPI.getPoRCertificateMode() == CertificationMode.DS)
			throw new PacketBuilderConfigurationException("Digital signature in response packets is not supported");
		if (responseSPI.getPoRCertificateMode() == CertificationMode.RC)
			throw new PacketBuilderConfigurationException("Redundancy checking in response packets is not supported");

		commandPacketCiphering = cardProfile.getSPI().getCommandSPI().isCiphered();
		responsePacketCiphering = cardProfile.getSPI().getResponseSPI().isCiphered();

		if (commandPacketCiphering || responsePacketCiphering)
			setCipheringAlgorithmName(cardProfile);

		commandPacketSigning = commandSPI.getCertificationMode() != CertificationMode.NO_SECURITY;
		responsePacketSigning = responseSPI.getPoRCertificateMode() != CertificationMode.NO_SECURITY;

		if (commandPacketSigning || responsePacketSigning)
			setSigningAlgorithmName(cardProfile);

		usingCounters = commandSPI.getSynchroCounterMode() != SynchroCounterMode.NO_COUNTER;

		if (LOGGER.isDebugEnabled() && !usingCounters)
			LOGGER.debug("Counters are turned off - counters field in CommandPacked will be filled with zeroes");

		try
		{
			this.cardProfile = copyProfile(cardProfile);
		}
		catch (Gsm0348Exception e)
		{
			throw new PacketBuilderConfigurationException("Cannot copy profile", e);
		}
	}

	private void setSigningAlgorithmName(CardProfile cardProfile) throws PacketBuilderConfigurationException
	{
		final KID kid = cardProfile.getKID();
		switch (kid.getAlgorithmImplementation())
		{
			case RESERVED:
				throw new PacketBuilderConfigurationException("Using reserved value for algorithm implementation in KID");

			case PROPRIETARY_IMPLEMENTATIONS:
			case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
				signatureAlgorithmName = cardProfile.getSignatureAlgorithm();
				if (signatureAlgorithmName == null || signatureAlgorithmName.isEmpty())
					throw new PacketBuilderConfigurationException(
							"In selected configuration signature algorithm name cannot be null or empty");
				break;
			case DES:
				switch (kid.getCertificationAlgorithmMode())
				{
					case DES_CBC:
						signatureAlgorithmName = SignatureManager.DES_MAC8_ISO9797_M1;
						break;

					case RESERVED:
						throw new PacketBuilderConfigurationException("Using reserved value for algorithm mode in KID");

					case TRIPLE_DES_CBC_2_KEYS:
					case TRIPLE_DES_CBC_3_KEYS:
						signatureAlgorithmName = "DESEDEMAC64";
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
			signatureSize = SignatureManager.signLength(signatureAlgorithmName);
		}
		catch (NoSuchAlgorithmException ex)
		{
			throw new PacketBuilderConfigurationException(ex);
		}
	}

	private void setCipheringAlgorithmName(CardProfile cardProfile) throws PacketBuilderConfigurationException
	{
		final KIC kic = cardProfile.getKIC();

		switch (kic.getAlgorithmImplementation())
		{
			case RESERVED:
				throw new PacketBuilderConfigurationException("Using reserved value for algorithm implementation in KIc");

			case PROPRIETARY_IMPLEMENTATIONS:
			case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
				cipheringAlgorithmName = cardProfile.getCipheringAlgorithm();
				if (cipheringAlgorithmName == null || cipheringAlgorithmName.isEmpty())
					throw new PacketBuilderConfigurationException(
							"In selected configuration ciphering algorithm name cannot be null or empty");
				break;
			case DES:
				switch (kic.getCipheringAlgorithmMode())
				{
					case DES_CBC:
						cipheringAlgorithmName = "DES/CBC/ZeroBytePadding";
						break;

					case DES_ECB:
						cipheringAlgorithmName = "DES/ECB/ZeroBytePadding";
						break;

					case TRIPLE_DES_CBC_2_KEYS:
					case TRIPLE_DES_CBC_3_KEYS:
						cipheringAlgorithmName = "DESede/CBC/ZeroBytePadding";
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
			cipherBlockSize = CipheringManager.getBlockSize(cipheringAlgorithmName);
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

	@Override
	public CardProfile getProfile()
	{
		try
		{
			return copyProfile(cardProfile);
		}
		catch (Gsm0348Exception e)
		{
			throw new IllegalStateException(e);
		}
	}

	@Override
	public boolean isConfigured()
	{
		return cardProfile != null;
	}

	private byte[] getSPI() throws CodingException
	{
		byte[] result = new byte[2];
		result[0] = CommandSPICoder.decode(cardProfile.getSPI().getCommandSPI());
		result[1] = ResponseSPICoder.decode(cardProfile.getSPI().getResponseSPI());
		return result;
	}

	@Override
	public byte[] buildCommandPacket(byte[] data, byte[] counters, byte[] cipheringKey, byte[] signatureKey)
			throws PacketBuilderConfigurationException, Gsm0348Exception
	{
		if (!isConfigured())
			throw new PacketBuilderConfigurationException("Not configured");

		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Creating command packet.\n\tData:" + Util.toHexArray(data) + "\n\tCounters:"
					+ Util.toHexArray(counters) + "\n\tCipheringKey:" + Util.toHexArray(cipheringKey) + "\n\tSigningKey:"
					+ Util.toHexArray(signatureKey));

		if (commandPacketCiphering && (cipheringKey == null))
			throw new PacketBuilderConfigurationException("Ciphering is enabled - ciphering key must be specified");
		if (commandPacketSigning && (signatureKey == null))
			throw new PacketBuilderConfigurationException("Signing is enabled - signature key must be specified");
		if (counters == null && usingCounters)
			throw new PacketBuilderConfigurationException("Counters are null and they are required by configuration");
		if (counters != null && counters.length != COUNTERS_SIZE)
			throw new PacketBuilderConfigurationException("Counters size mismatch. Current = "
					+ (counters != null ? counters.length : "counter == null") + ". Required:" + COUNTERS_SIZE);

		try
		{
			final int signatureLength = commandPacketSigning ? signatureSize : 0;
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Signature length: " + signatureLength);
			final int headerLenght = HEADER_SIZE_WITOUT_SIGNATURE + HEADER_LENGHT_SIZE + signatureLength;
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Header length(including size byte): " + headerLenght);

			byte[] signature = new byte[signatureLength];
			byte[] headerData = new byte[headerLenght];
			byte[] dataBytes = (data == null) ? new byte[0] : data;
			byte[] countersBytes = usingCounters ? counters : new byte[COUNTERS_SIZE];
			byte paddingCounter = 0;

			headerData[HEADER_LENGHT_POSITION] = (byte) (headerLenght - HEADER_LENGHT_SIZE);
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Header length value: " + headerData[HEADER_LENGHT_POSITION]);
			System.arraycopy(getSPI(), 0, headerData, SPI_POSITION, SPI_SIZE);
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("SPI value: "
						+ Util.toHexArray(Arrays.copyOfRange(headerData, SPI_POSITION, SPI_POSITION + SPI_SIZE)));
			headerData[KIC_POSITION] = KICCoder.decode(cardProfile.getKIC());
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("KIc value: " + Util.toHex(headerData[KIC_POSITION]));
			headerData[KID_POSITION] = KIDCoder.decode(cardProfile.getKID());
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("KID value: " + Util.toHex(headerData[KID_POSITION]));
			System.arraycopy(cardProfile.getTAR(), 0, headerData, TAR_POSITION, TAR_SIZE);
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("TAR value: "
						+ Util.toHexArray(Arrays.copyOfRange(headerData, TAR_POSITION, TAR_POSITION + TAR_SIZE)));
			System.arraycopy(countersBytes, 0, headerData, COUNTERS_POSITION, COUNTERS_SIZE);
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("COUNTERS value: "
						+ Util.toHexArray(Arrays.copyOfRange(headerData, COUNTERS_POSITION, COUNTERS_POSITION + COUNTERS_SIZE)));

			if (commandPacketCiphering)
			{
				final int dataSize = COUNTERS_SIZE + PADDING_COUNTER_SIZE + signatureLength + dataBytes.length;
				int remainder = dataSize % cipherBlockSize;
				if (remainder != 0)
					paddingCounter = (byte) (cipherBlockSize - remainder);

			}
			headerData[PADDING_COUNTER_POSITION] = paddingCounter;

			if (LOGGER.isDebugEnabled())
				LOGGER.debug(String.format("Padding counter value:%X", headerData[PADDING_COUNTER_POSITION]));

			if (commandPacketSigning)
			{
				if (LOGGER.isDebugEnabled())
					LOGGER.debug("Signing");
				byte[] signData = new byte[headerLenght + dataBytes.length - signatureLength + PACKET_LENGHT_SIZE
						+ paddingCounter];
				if (LOGGER.isDebugEnabled())
					LOGGER.debug("Signing data length: " + signData.length);
				final int length = dataBytes.length + paddingCounter + headerLenght;
				signData[0] = (byte) ((length >> 8) & 0xFF);
				signData[1] = (byte) ((length & 0xFF));
				System.arraycopy(headerData, 0, signData, 2, headerLenght - signatureLength);
				System.arraycopy(dataBytes, 0, signData, headerLenght - signatureLength + 2, dataBytes.length);
				if (LOGGER.isDebugEnabled())
					LOGGER.debug("Signing data : " + Util.toHexArray(signData));
				signature = SignatureManager.sign(signatureAlgorithmName, signatureKey, signData);
			}
			System.arraycopy(signature, 0, headerData, SIGNATURE_POSITION, signatureLength);

			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Signature value: " + Util.toHexArray(signature));

			if (commandPacketCiphering)
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

				byte[] cipheredData = CipheringManager.encipher(cipheringAlgorithmName, cipheringKey, cipherData, countersBytes);
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
			byte[] result = new byte[headerData.length + dataBytes.length + PACKET_LENGHT_SIZE];

			result[0] = (byte) (((headerData.length + dataBytes.length) >> 8) & 0xFF);
			result[1] = (byte) (((headerData.length + dataBytes.length) & 0xFF));
			System.arraycopy(headerData, 0, result, PACKET_LENGHT_SIZE, headerData.length);
			System.arraycopy(dataBytes, 0, result, headerData.length + PACKET_LENGHT_SIZE, dataBytes.length);

			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Packet created : " + Util.toHexArray(result));
			return result;
		}
		catch (GeneralSecurityException e)
		{
			throw new Gsm0348Exception(e);
		}
	}

	@Override
	public ResponsePacket recoverResponsePacket(byte[] data, byte[] cipheringKey, byte[] signatureKey)
			throws PacketBuilderConfigurationException, Gsm0348Exception
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Recovering response packet.\n\tData:" + Util.toHexArray(data) + "\n\tCipheringKey:"
					+ Util.toHexArray(cipheringKey) + "\n\tSigningKey:" + Util.toHexArray(signatureKey));

		if (!isConfigured())
			throw new PacketBuilderConfigurationException("Not configured");

		if (data == null)
			throw new IllegalArgumentException("packet data cannot be null");

		if (responsePacketCiphering && (cipheringKey == null || cipheringKey.length == 0))
			throw new PacketBuilderConfigurationException(
					"Response ciphering is enabled - ciphering key must be specified. Provided: "
							+ ((cipheringKey.length == 0) ? "empty" : Util.toHexArray(cipheringKey)));
		if (responsePacketSigning && (signatureKey == null || signatureKey.length == 0))
			throw new PacketBuilderConfigurationException(
					"Response signing is enabled - signature key must be specified. Provided: "
							+ ((signatureKey.length == 0) ? "empty" : Util.toHexArray(signatureKey)));

		final int packetLength = Util.unsignedByteToInt(data[0]) + Util.unsignedByteToInt(data[1]);
		if (data.length - PACKET_LENGHT_SIZE != packetLength)
			throw new Gsm0348Exception("Length of raw data doesnt match packet length. Expected " + packetLength + " but found "
					+ (data.length - PACKET_LENGHT_SIZE));

		final int headerLength = Util.unsignedByteToInt(data[HEADER_LENGHT_RESPONSE_POSITION]);
		final byte[] tar = new byte[TAR_SIZE];
		System.arraycopy(data, TAR_RESPONSE_POSITION, tar, 0, TAR_SIZE);
		final byte[] counters = new byte[COUNTERS_SIZE];
		final int signatureLength = responsePacketSigning ? signatureSize : 0;

		if (data.length < MINIMUM_RESPONSE_PACKET_SIZE + signatureLength)
		{
			String message = "rawdata too small to be response packet. Expected to be >= "
					+ (MINIMUM_RESPONSE_PACKET_SIZE + signatureLength) + ", but found " + data.length;
			if (data.length >= MINIMUM_RESPONSE_PACKET_SIZE)
			{
				message += ". It can be caused by incorrect profile(SPI value). Check SPI!";
				if (LOGGER.isEnabledFor(Level.WARN))
					LOGGER.warn("Packet recived(raw): " + Util.toHexArray(data));
			}
			throw new Gsm0348Exception(message);
		}

		final byte[] signature = new byte[signatureLength];
		int paddingCounter = Util.unsignedByteToInt(data[PADDING_COUNTER_RESPONSE_POSITION]);
		if (!responsePacketCiphering && paddingCounter != 0)
			throw new Gsm0348Exception(
					"Response packet ciphering is off but padding counter isnot 0. So it can be corrupted packet or configuration doesn`t match provided data");
		byte responseCode = 0;
		byte[] packetData;
		try
		{
			if (responsePacketCiphering)
			{
				byte[] dataEnc = CipheringManager.decipher(cipheringAlgorithmName, cipheringKey,
						Arrays.copyOfRange(data, 6, data.length));
				System.arraycopy(dataEnc, 0, counters, 0, COUNTERS_SIZE);
				paddingCounter = Util.unsignedByteToInt(dataEnc[COUNTERS_SIZE]);
				responseCode = dataEnc[COUNTERS_SIZE + 1];
				if (dataEnc.length < COUNTERS_SIZE + 2 + signatureLength)
					throw new Gsm0348Exception(
							"Packet recovery failure. Possibly because of unexpected security bytes length. Expected: "
									+ signatureSize);
				System.arraycopy(dataEnc, COUNTERS_SIZE + 2, signature, 0, signatureLength);
				// Modified by Tomas Andersen / Morecom AS 2014.04.08 - TEST CASE: Tomas Andersen Bug #1->
				
				// Old code->
//				final int dataSize = dataEnc.length - TAR_SIZE - HEADER_LENGHT_SIZE;
//				packetData = new byte[dataSize];
//				System.arraycopy(dataEnc, COUNTERS_SIZE + 2 + signatureLength, packetData, 0, dataSize);
				// <- End of old code
				// New code->
				final int dataSize = packetLength - headerLength - HEADER_LENGHT_SIZE;
		        final int dataSizeToCopy = dataEnc.length - COUNTERS_SIZE - PADDING_COUNTER_SIZE - RESPONSE_CODE_RESPONSE_SIZE - signatureLength;
		        
		        packetData = new byte[dataSize];

		        System.arraycopy(dataEnc, COUNTERS_SIZE + 2 + signatureLength, packetData, 0, dataSizeToCopy);
//				<- End of new code
//				End of modification by Tomas Andersen / Morecom AS 2014.04.08 - TEST CASE: Tomas Andersen Bug #1->
			}
			else
			{
				System.arraycopy(data, COUNTERS_RESPONSE_POSITION, counters, 0, COUNTERS_SIZE);
				paddingCounter = Util.unsignedByteToInt(data[PADDING_COUNTER_RESPONSE_POSITION]);
				responseCode = data[RESPONSE_CODE_RESPONSE_POSITION];
				System.arraycopy(data, SIGNATURE_RESPONSE_POSITION, signature, 0, signatureLength);
				final int dataSize = packetLength - headerLength - HEADER_LENGHT_SIZE;
				packetData = new byte[dataSize];
				System.arraycopy(data, headerLength + HEADER_LENGHT_SIZE + PACKET_LENGHT_SIZE, packetData, 0, dataSize);
			}

			if (responsePacketSigning)
			{
				int addonAmount = 0;
				if (cardProfile.getSecurityBytesType() == SecurityBytesType.WITH_LENGHTS_AND_UDHL)
					addonAmount = 6;
				else if (cardProfile.getSecurityBytesType() == SecurityBytesType.WITH_LENGHTS)
					addonAmount = 3;

				byte[] signData = new byte[addonAmount + TAR_SIZE + PADDING_COUNTER_SIZE + RESPONSE_CODE_RESPONSE_SIZE
						+ COUNTERS_SIZE + packetData.length];
				switch (cardProfile.getSecurityBytesType())
				{
					case WITH_LENGHTS_AND_UDHL:
						signData[0] = 0x02;
						signData[1] = 0x71;
						signData[2] = 0x00;
						System.arraycopy(data, 0, signData, 3, 3);
						break;
					case WITH_LENGHTS:
						System.arraycopy(data, 0, signData, 0, 3);
						break;
				}

				System.arraycopy(tar, 0, signData, addonAmount, TAR_SIZE);
				System.arraycopy(counters, 0, signData, addonAmount + TAR_SIZE, COUNTERS_SIZE);
				signData[addonAmount + TAR_SIZE + COUNTERS_SIZE] = (byte) paddingCounter;
				signData[addonAmount + TAR_SIZE + COUNTERS_SIZE + 1] = responseCode;
				System.arraycopy(packetData, 0, signData, addonAmount + TAR_SIZE + COUNTERS_SIZE + 2, packetData.length);

				boolean valid = SignatureManager.verify(signatureAlgorithmName, signatureKey, signData, signature);
				if (!valid)
					throw new Gsm0348Exception("Signatures doesnt match");
			}

			ResponsePacketHeader pacHeader = new ResponsePacketHeader();
			pacHeader.setCounter(counters);
			pacHeader.setPaddingCounter((byte) paddingCounter);
			pacHeader.setResponseStatus(ResponsePacketStatusCoder.encode(responseCode));
			pacHeader.setSecurity(signature);
			pacHeader.setTAR(tar);

			ResponsePacket pac = new ResponsePacket();
			pac.setData(packetData);
			pac.setHeader(pacHeader);

			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Packet recovered : " + pac);
			return pac;
		}
		catch (GeneralSecurityException e)
		{
			throw new Gsm0348Exception(e);
		}
	}

	@Override
	@Deprecated
	public byte[] buildResponsePacket(byte[] data, byte[] counters, byte[] cipheringKey, byte[] signatureKey,
			ResponsePacketStatus responseStatus) throws PacketBuilderConfigurationException, Gsm0348Exception
	{
		throw new Gsm0348Exception("Not implemented yet");
	}

	@Override
	@Deprecated
	public CommandPacket recoverCommandPacket(byte[] data, byte[] cipheringKey, byte[] signatureKey)
			throws PacketBuilderConfigurationException, Gsm0348Exception
	{
		throw new Gsm0348Exception("Not implemented yet");
	}

}
