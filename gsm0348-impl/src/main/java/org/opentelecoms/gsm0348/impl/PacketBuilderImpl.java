package org.opentelecoms.gsm0348.impl;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.NoSuchPaddingException;

import org.apache.commons.beanutils.BeanUtils;
import org.opentelecoms.gsm0348.api.Gsm0348Exception;
import org.opentelecoms.gsm0348.api.PacketBuilder;
import org.opentelecoms.gsm0348.api.PacketBuilderConfigurationException;
import org.opentelecoms.gsm0348.api.Util;
import org.opentelecoms.gsm0348.api.model.CardProfile;
import org.opentelecoms.gsm0348.api.model.CertificationMode;
import org.opentelecoms.gsm0348.api.model.CommandPacket;
import org.opentelecoms.gsm0348.api.model.CommandPacketHeader;
import org.opentelecoms.gsm0348.api.model.CommandSPI;
import org.opentelecoms.gsm0348.api.model.KIC;
import org.opentelecoms.gsm0348.api.model.KID;
import org.opentelecoms.gsm0348.api.model.ResponsePacket;
import org.opentelecoms.gsm0348.api.model.ResponsePacketHeader;
import org.opentelecoms.gsm0348.api.model.ResponsePacketStatus;
import org.opentelecoms.gsm0348.api.model.ResponseSPI;
import org.opentelecoms.gsm0348.api.model.SPI;
import org.opentelecoms.gsm0348.api.model.SecurityBytesType;
import org.opentelecoms.gsm0348.api.model.SynchroCounterMode;
import org.opentelecoms.gsm0348.impl.coders.CommandSPICoder;
import org.opentelecoms.gsm0348.impl.coders.KICCoder;
import org.opentelecoms.gsm0348.impl.coders.KIDCoder;
import org.opentelecoms.gsm0348.impl.coders.ResponsePacketStatusCoder;
import org.opentelecoms.gsm0348.impl.coders.ResponseSPICoder;
import org.opentelecoms.gsm0348.impl.crypto.CipheringManager;
import org.opentelecoms.gsm0348.impl.crypto.SignatureManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketBuilderImpl implements PacketBuilder {
  private static final Logger LOGGER = LoggerFactory.getLogger(PacketBuilderImpl.class);
  private static final int PACKET_LENGTH_SIZE = 2;
  private static final int HEADER_LENGTH_POSITION = 0;
  private static final int HEADER_LENGTH_RESPONSE_POSITION = 2;
  private static final int HEADER_LENGTH_SIZE = 1;
  private static final int SPI_POSITION = 1;
  private static final int SPI_SIZE = 2;
  private static final int KIC_POSITION = 3;
  private static final int KIC_SIZE = 1;
  private static final int KID_POSITION = 4;
  private static final int KID_SIZE = 1;
  private static final int TAR_POSITION = 5;
  private static final int TAR_RESPONSE_POSITION = 1;
  private static final int TAR_SIZE = 3;
  private static final int COUNTERS_POSITION = 8;
  private static final int COUNTERS_RESPONSE_POSITION = 4;
  private static final int COUNTERS_SIZE = 5;
  private static final int PADDING_COUNTER_POSITION = 13;
  private static final int PADDING_COUNTER_RESPONSE_POSITION = 9;
  private static final int PADDING_COUNTER_SIZE = 1;
  private static final int RESPONSE_CODE_RESPONSE_POSITION = 12;
  private static final int RESPONSE_CODE_RESPONSE_SIZE = 1;
  private static final int SIGNATURE_POSITION = 14;
  private static final int SIGNATURE_RESPONSE_POSITION = 13;
  private static final int MINIMUM_COMMAND_PACKET_SIZE = 16;
  private static final int MINIMUM_RESPONSE_PACKET_SIZE = 13;
  private static final int HEADER_SIZE_WITHOUT_SIGNATURE = SPI_SIZE + KIC_SIZE + KID_SIZE + TAR_SIZE + COUNTERS_SIZE + PADDING_COUNTER_SIZE;
  private static final int STATUS_CODE_SIZE = 1;
  private static final int STATUS_CODE_RESPONSE_POSITION = 10;
  private static final int RESPONSE_HEADER_SIZE_WITHOUT_SIGNATURE = TAR_SIZE + COUNTERS_SIZE + PADDING_COUNTER_SIZE + STATUS_CODE_SIZE;

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

  // https://www.etsi.org/deliver/etsi_ts/131100_131199/131115/06.05.00_60/ts_131115v060500p.pdf

  public PacketBuilderImpl() {
  }

  public PacketBuilderImpl(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    setProfile(cardProfile);
  }

  private CardProfile copyProfile(CardProfile profile) throws Gsm0348Exception {
    try {
      return (CardProfile) BeanUtils.cloneBean(profile);
    } catch (Exception ex) {
      throw new Gsm0348Exception(ex);
    }
  }

  private void verifyProfile(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    if (cardProfile == null) {
      throw new PacketBuilderConfigurationException("CardProfile cannot be null");
    }

    if (cardProfile.getSPI() == null) {
      throw new PacketBuilderConfigurationException("SPI cannot be null");
    }
    if (cardProfile.getSPI().getCommandSPI() == null) {
      throw new PacketBuilderConfigurationException("CommandSPI cannot be null");
    }
    if (cardProfile.getSPI().getCommandSPI().getCertificationMode() == null) {
      throw new PacketBuilderConfigurationException("CommandSPI CertificationMode cannot be null");
    }
    if (cardProfile.getSPI().getCommandSPI().getSynchroCounterMode() == null) {
      throw new PacketBuilderConfigurationException("CommandSPI SynchroCounterMode cannot be null");
    }
    if (cardProfile.getSPI().getResponseSPI() == null) {
      throw new PacketBuilderConfigurationException("ResponseSPI cannot be null");
    }
    if (cardProfile.getSPI().getResponseSPI().getPoRCertificateMode() == null) {
      throw new PacketBuilderConfigurationException("ResponseSPI PoRCertificateMode cannot be null");
    }
    if (cardProfile.getSPI().getResponseSPI().getPoRMode() == null) {
      throw new PacketBuilderConfigurationException("ResponseSPI PoRMode cannot be null");
    }
    if (cardProfile.getSPI().getResponseSPI().getPoRProtocol() == null) {
      throw new PacketBuilderConfigurationException("ResponseSPI PoRProtocol cannot be null");
    }

    final boolean commandCiphered = cardProfile.getSPI().getCommandSPI().isCiphered();
    if (cardProfile.getKIC() == null) {
      throw new PacketBuilderConfigurationException("KIC cannot be null");
    }
    if (cardProfile.getKIC().getAlgorithmImplementation() == null) {
      throw new PacketBuilderConfigurationException("KIC AlgorithmImplementation cannot be null");
    }
    if (commandCiphered && cardProfile.getKIC().getCipheringAlgorithmMode() == null) {
      throw new PacketBuilderConfigurationException("KIC CipheringAlgorithmMode cannot be null for ciphered command");
    }
    if (cardProfile.getKIC().getKeysetID() < 0x0 || cardProfile.getKIC().getKeysetID() > (byte) 0xf) {
      throw new PacketBuilderConfigurationException("KIC keySetID cannot be <0 and >15");
    }

    final boolean responseCiphered = cardProfile.getSPI().getResponseSPI().isCiphered();
    if (cardProfile.getKID() == null) {
      throw new PacketBuilderConfigurationException("KID cannot be null");
    }
    if (responseCiphered && cardProfile.getKID().getAlgorithmImplementation() == null) {
      throw new PacketBuilderConfigurationException("KID AlgorithmImplementation cannot be null for ciphered response");
    }
    if (responseCiphered && cardProfile.getKID().getCertificationAlgorithmMode() == null) {
      throw new PacketBuilderConfigurationException("KID CertificationAlgorithmMode cannot be null for ciphered response");
    }
    if (cardProfile.getKID().getKeysetID() < 0x0 || cardProfile.getKID().getKeysetID() > (byte) 0xf) {
      throw new PacketBuilderConfigurationException("KID keySetID cannot be <0 and >15");
    }

    if (cardProfile.getSecurityBytesType() == null) {
      throw new PacketBuilderConfigurationException("SecurityBytesType cannot be null");
    }

    if (cardProfile.getTAR() == null || cardProfile.getTAR().length != 3) {
      throw new PacketBuilderConfigurationException("TAR value null or not a 3 bytes array");
    }
  }

  private void setSigningAlgorithmName(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    final KID kid = cardProfile.getKID();
    switch (kid.getAlgorithmImplementation()) {
      case PROPRIETARY_IMPLEMENTATIONS:
      case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
        signatureAlgorithmName = cardProfile.getSignatureAlgorithm();
        if (signatureAlgorithmName == null || signatureAlgorithmName.isEmpty()) {
          throw new PacketBuilderConfigurationException(
              "In selected configuration signature algorithm name cannot be null or empty");
        }
        break;
      case DES:
        switch (kid.getCertificationAlgorithmMode()) {
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
      case AES:
        switch (kid.getCertificationAlgorithmMode()) {
          case AES_CMAC:
            final String signatureAlgorithm = cardProfile.getSignatureAlgorithm();
            if (signatureAlgorithm == null || signatureAlgorithm.isEmpty()) {
              throw new PacketBuilderConfigurationException(
                  "In selected configuration signature algorithm name cannot be null or empty");
            }
            if (!SignatureManager.AES_CMAC_32.equals(signatureAlgorithm) && !SignatureManager.AES_CMAC_64.equals(signatureAlgorithm)) {
              throw new PacketBuilderConfigurationException(
                  "For AES CMAC, the signature can only be AES_CMAC_32 or AES_CMAC_64, but was " + signatureAlgorithm);
            }
            signatureAlgorithmName = cardProfile.getSignatureAlgorithm();
            break;
          default:
            throw new PacketBuilderConfigurationException("Not implemented yet");
        }
        break;
      case CRC:
        switch (kid.getCertificationAlgorithmMode()) {
          case CRC_16:
            signatureAlgorithmName = SignatureManager.CRC_16;
            break;
          case CRC_32:
            signatureAlgorithmName = SignatureManager.CRC_32;
            break;
          default:
            throw new PacketBuilderConfigurationException("Not implemented yet");
        }
        break;
      default:
        throw new PacketBuilderConfigurationException("Not implemented yet");
    }
    try {
      signatureSize = SignatureManager.signLength(signatureAlgorithmName);
    } catch (NoSuchAlgorithmException ex) {
      throw new PacketBuilderConfigurationException(ex);
    }
  }

  private void setCipheringAlgorithmName(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    final KIC kic = cardProfile.getKIC();
    switch (kic.getAlgorithmImplementation()) {
      case PROPRIETARY_IMPLEMENTATIONS:
      case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
        cipheringAlgorithmName = cardProfile.getCipheringAlgorithm();
        if (cipheringAlgorithmName == null || cipheringAlgorithmName.isEmpty()) {
          throw new PacketBuilderConfigurationException(
              "In selected configuration ciphering algorithm name cannot be null or empty");
        }
        break;
      case DES:
        switch (kic.getCipheringAlgorithmMode()) {
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
      case AES:
        switch (kic.getCipheringAlgorithmMode()) {
          case AES_CBC:
            cipheringAlgorithmName = "AES/CBC/ZeroBytePadding";
            break;
          default:
            throw new PacketBuilderConfigurationException("Not implemented yet");
        }
        break;
      default:
        throw new PacketBuilderConfigurationException("Not implemented yet");
    }
    try {
      cipherBlockSize = CipheringManager.getBlockSize(cipheringAlgorithmName);
    } catch (NoSuchAlgorithmException ex) {
      throw new PacketBuilderConfigurationException(ex);
    } catch (NoSuchPaddingException ex) {
      throw new PacketBuilderConfigurationException(ex);
    }
  }

  @Override
  public CardProfile getProfile() {
    try {
      return copyProfile(cardProfile);
    } catch (Gsm0348Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public void setProfile(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    verifyProfile(cardProfile);

    CommandSPI commandSPI = cardProfile.getSPI().getCommandSPI();
    ResponseSPI responseSPI = cardProfile.getSPI().getResponseSPI();

    if (commandSPI.getCertificationMode() == CertificationMode.DS) {
      throw new PacketBuilderConfigurationException("Digital signature in command packets is not supported");
    }
    if (responseSPI.getPoRCertificateMode() == CertificationMode.DS) {
      throw new PacketBuilderConfigurationException("Digital signature in response packets is not supported");
    }
    commandPacketCiphering = cardProfile.getSPI().getCommandSPI().isCiphered();
    responsePacketCiphering = cardProfile.getSPI().getResponseSPI().isCiphered();

    if (commandPacketCiphering || responsePacketCiphering) {
      setCipheringAlgorithmName(cardProfile);
    }

    commandPacketSigning = commandSPI.getCertificationMode() != CertificationMode.NO_SECURITY;
    responsePacketSigning = responseSPI.getPoRCertificateMode() != CertificationMode.NO_SECURITY;

    if (commandPacketSigning || responsePacketSigning) {
      setSigningAlgorithmName(cardProfile);
    }

    usingCounters = commandSPI.getSynchroCounterMode() != SynchroCounterMode.NO_COUNTER;

    if (!usingCounters) {
      LOGGER.debug("Counters are turned off - counters field in CommandPacket will be filled with zeroes");
    }

    try {
      this.cardProfile = copyProfile(cardProfile);
    } catch (Gsm0348Exception e) {
      throw new PacketBuilderConfigurationException("Cannot copy profile", e);
    }
  }

  @Override
  public boolean isConfigured() {
    return cardProfile != null;
  }

  private byte[] getSPI() throws CodingException {
    byte[] result = new byte[2];
    result[0] = CommandSPICoder.decode(cardProfile.getSPI().getCommandSPI());
    result[1] = ResponseSPICoder.decode(cardProfile.getSPI().getResponseSPI());
    return result;
  }

  private SPI getSPI(byte[] data) throws CodingException {
    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode(data[0]));
    spi.setResponseSPI(ResponseSPICoder.encode(data[1]));
    return spi;
  }

  @Override
  public byte[] buildCommandPacket(byte[] data, byte[] counter, byte[] cipheringKey, byte[] signatureKey)
      throws PacketBuilderConfigurationException, Gsm0348Exception {
    if (!isConfigured()) {
      throw new PacketBuilderConfigurationException("Not configured");
    }

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Creating command packet.\n\tData: {}\n\tCounter: {}\n\tCipheringKey: {}\n\tSigningKey: {}"
          , Util.toHexString(data)
          , Util.toHexString(counter)
          , Util.toHexString(cipheringKey)
          , Util.toHexString(signatureKey));
    }

    if (commandPacketCiphering && (cipheringKey == null)) {
      throw new PacketBuilderConfigurationException("Ciphering is enabled - ciphering key must be specified");
    }
    if (commandPacketSigning && (signatureKey == null)) {
      throw new PacketBuilderConfigurationException("Signing is enabled - signature key must be specified");
    }
    if (counter == null && usingCounters) {
      throw new PacketBuilderConfigurationException("Counters are null and they are required by configuration");
    }
    if (counter != null && counter.length != COUNTERS_SIZE) {
      throw new PacketBuilderConfigurationException("Counters size mismatch. Current = "
          + (counter != null ? counter.length : "counter == null") + ". Required:" + COUNTERS_SIZE);
    }

    try {
      final int signatureLength = commandPacketSigning ? signatureSize : 0;
      LOGGER.debug("Signature length: {}", signatureLength);
      final int headerLength = HEADER_SIZE_WITHOUT_SIGNATURE + HEADER_LENGTH_SIZE + signatureLength;
      LOGGER.debug("Header length (including size byte): {}", headerLength);

      byte[] signature = new byte[signatureLength];
      byte[] headerData = new byte[headerLength];
      byte[] dataBytes = (data == null) ? new byte[0] : data;
      byte[] countersBytes = usingCounters ? counter : new byte[COUNTERS_SIZE];
      byte paddingCounter = 0;

      headerData[HEADER_LENGTH_POSITION] = (byte) (headerLength - HEADER_LENGTH_SIZE);
      LOGGER.debug("Header length value: {}", headerData[HEADER_LENGTH_POSITION]);
      System.arraycopy(getSPI(), 0, headerData, SPI_POSITION, SPI_SIZE);
      LOGGER.debug("SPI value: " + Util.toHexArray(Arrays.copyOfRange(headerData, SPI_POSITION, SPI_POSITION + SPI_SIZE)));
      headerData[KIC_POSITION] = KICCoder.decode(cardProfile.getKIC());
      LOGGER.debug("KIC value: {}", Util.toHex(headerData[KIC_POSITION]));
      headerData[KID_POSITION] = KIDCoder.decode(cardProfile.getKID());
      LOGGER.debug("KID value: {}", Util.toHex(headerData[KID_POSITION]));
      System.arraycopy(cardProfile.getTAR(), 0, headerData, TAR_POSITION, TAR_SIZE);
      LOGGER.debug("TAR value: {}", Util.toHexArray(Arrays.copyOfRange(headerData, TAR_POSITION, TAR_POSITION + TAR_SIZE)));
      System.arraycopy(countersBytes, 0, headerData, COUNTERS_POSITION, COUNTERS_SIZE);
      LOGGER.debug("COUNTERS value: {}", Util.toHexArray(Arrays.copyOfRange(headerData, COUNTERS_POSITION, COUNTERS_POSITION + COUNTERS_SIZE)));

      if (commandPacketCiphering) {
        final int dataSize = COUNTERS_SIZE + PADDING_COUNTER_SIZE + signatureLength + dataBytes.length;
        paddingCounter = (byte) (getPadding(dataSize, cipherBlockSize) & 0xff);
      }
      headerData[PADDING_COUNTER_POSITION] = paddingCounter;
      LOGGER.debug("Padding counter value: {}", String.format("0x%02X", headerData[PADDING_COUNTER_POSITION]));

      if (commandPacketSigning) {
        byte[] signData = new byte[headerLength + dataBytes.length - signatureLength + PACKET_LENGTH_SIZE + paddingCounter];
        final int length = dataBytes.length + paddingCounter + headerLength;
        signData[0] = (byte) ((length >> 8) & (byte) 0xff);
        signData[1] = (byte) ((length & (byte) 0xff));
        System.arraycopy(headerData, 0, signData, 2, headerLength - signatureLength);
        System.arraycopy(dataBytes, 0, signData, headerLength - signatureLength + 2, dataBytes.length);
        LOGGER.debug("Signing data: {} length: {} ({})", Util.toHexString(signData), signData.length, signatureAlgorithmName);
        signature = SignatureManager.sign(signatureAlgorithmName, signatureKey, signData);
      }
      if (signature.length != signatureLength) {
        throw new Gsm0348Exception("The generated signature length doesn't match the expected length");
      }
      System.arraycopy(signature, 0, headerData, SIGNATURE_POSITION, signatureLength);

      LOGGER.debug("Signature value: {} length: {}", Util.toHexString(signature), signature.length);
      LOGGER.debug("Header: {} length: {}", Util.toHexString(headerData), headerData.length);

      if (commandPacketCiphering) {
        byte[] cipherData = new byte[COUNTERS_SIZE + PADDING_COUNTER_SIZE + signatureLength + dataBytes.length];
        System.arraycopy(countersBytes, 0, cipherData, 0, COUNTERS_SIZE);
        cipherData[5] = paddingCounter;
        System.arraycopy(signature, 0, cipherData, 6, signatureLength);
        System.arraycopy(dataBytes, 0, cipherData, 6 + signatureLength, dataBytes.length);
        // dataBytes = new byte[dataBytes.length + paddingCounter];

        LOGGER.debug("Ciphering data: {} length: {}", Util.toHexString(cipherData), cipherData.length);
        byte[] cipheredData = CipheringManager.encipher(cipheringAlgorithmName, cipheringKey, cipherData, countersBytes);
        LOGGER.debug("Ciphered data: {} length: {}", Util.toHexString(cipheredData), cipheredData.length);

        final byte[] headerCiphered = new byte[8];
        System.arraycopy(headerData, 0, headerCiphered, 0, headerCiphered.length);
        final byte[] cipheredDataBytesPadded = new byte[cipherData.length + paddingCounter];
        System.arraycopy(cipheredData, 0, cipheredDataBytesPadded, 0, cipheredDataBytesPadded.length);
        LOGGER.debug("Ciphered command data: {} length: {}", Util.toHexString(cipheredDataBytesPadded), cipheredDataBytesPadded.length);
        LOGGER.debug("Ciphered command header data: {} length: {}", Util.toHexString(headerCiphered), headerCiphered.length);
        byte[] result = createPacket(headerCiphered, cipheredDataBytesPadded);
        LOGGER.debug("Ciphered command packet created: {} length: {}", Util.toHexString(result), result.length);
        return result;
      }
      LOGGER.debug("Command header raw data: {} length: {}", Util.toHexString(headerData), headerData.length);
      byte[] result = createPacket(headerData, dataBytes);
      LOGGER.debug("Command packet created: {} length: {}", Util.toHexString(result), result.length);
      return result;
    } catch (GeneralSecurityException e) {
      throw new Gsm0348Exception(e);
    }
  }

  @Override
  public ResponsePacket recoverResponsePacket(byte[] data, byte[] cipheringKey, byte[] signatureKey)
      throws PacketBuilderConfigurationException, Gsm0348Exception {
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Recovering response packet.\n\tData: {}\n\tCipheringKey: {}\n\tSigningKey: {}",
          Util.toHexArray(data),
          Util.toHexArray(cipheringKey),
          Util.toHexArray(signatureKey));
    }

    if (!isConfigured()) {
      throw new PacketBuilderConfigurationException("Not configured");
    }

    if (data == null) {
      throw new IllegalArgumentException("Packet data cannot be null");
    }

    if (responsePacketCiphering && (cipheringKey == null || cipheringKey.length == 0)) {
      throw new PacketBuilderConfigurationException(
          "Response ciphering is enabled - ciphering key must be specified. Provided: "
              + ((cipheringKey.length == 0) ? "empty" : Util.toHexArray(cipheringKey)));
    }
    if (responsePacketSigning && (signatureKey == null || signatureKey.length == 0)) {
      throw new PacketBuilderConfigurationException(
          "Response signing is enabled - signature key must be specified. Provided: "
              + ((signatureKey.length == 0) ? "empty" : Util.toHexArray(signatureKey)));
    }

    final int packetLength = (Util.byteToInt(data[0]) >> 8) + Util.byteToInt(data[1]);
    if (data.length - PACKET_LENGTH_SIZE != packetLength) {
      throw new Gsm0348Exception("Length of raw data doesnt match packet length. Expected " + packetLength + " but found "
          + (data.length - PACKET_LENGTH_SIZE));
    }

    final int headerLength = Util.byteToInt(data[HEADER_LENGTH_RESPONSE_POSITION]);
    final byte[] tar = new byte[TAR_SIZE];
    System.arraycopy(data, 2 + TAR_RESPONSE_POSITION, tar, 0, TAR_SIZE);
    final byte[] counters = new byte[COUNTERS_SIZE];
    final int signatureLength = responsePacketSigning ? signatureSize : 0;

    if (data.length < MINIMUM_RESPONSE_PACKET_SIZE + signatureLength) {
      String message = "rawdata too small to be response packet. Expected to be >= "
          + (MINIMUM_RESPONSE_PACKET_SIZE + signatureLength) + ", but found " + data.length;
      if (data.length >= MINIMUM_RESPONSE_PACKET_SIZE) {
        message += ". It can be caused by incorrect profile(SPI value). Check SPI!";
        LOGGER.warn("Packet received(raw): {}", Util.toHexArray(data));
      }
      throw new Gsm0348Exception(message);
    }

    final byte[] signature = new byte[signatureLength];
    int paddingCounter = Util.byteToInt(data[PADDING_COUNTER_RESPONSE_POSITION - 2]);
    if (!responsePacketCiphering && paddingCounter != 0) {
      throw new Gsm0348Exception(
          "Response packet ciphering is off but padding counter is not 0. So it can be corrupted packet or configuration doesn't match provided data");
    }
    byte responseCode = 0;
    byte[] packetData;
    try {
      if (responsePacketCiphering) {
        byte[] dataEnc = CipheringManager.decipher(cipheringAlgorithmName, cipheringKey,
            Arrays.copyOfRange(data, 6, data.length));
        System.arraycopy(dataEnc, 0, counters, 0, COUNTERS_SIZE);
        paddingCounter = Util.byteToInt(dataEnc[COUNTERS_SIZE]);
        responseCode = dataEnc[COUNTERS_SIZE + 1];
        if (dataEnc.length < COUNTERS_SIZE + 2 + signatureLength) {
          throw new Gsm0348Exception(
              "Packet recovery failure. Possibly because of unexpected security bytes length. Expected: "
                  + signatureSize);
        }
        System.arraycopy(dataEnc, COUNTERS_SIZE + 2, signature, 0, signatureLength);
        // Modified by Tomas Andersen / Morecom AS 2014.04.08 - TEST CASE: Tomas Andersen Bug #1->

        // Old code->
//				final int dataSize = dataEnc.length - TAR_SIZE - HEADER_LENGHT_SIZE;
//				packetData = new byte[dataSize];
//				System.arraycopy(dataEnc, COUNTERS_SIZE + 2 + signatureLength, packetData, 0, dataSize);
        // <- End of old code
        // New code->
        final int dataSize = packetLength - headerLength - HEADER_LENGTH_SIZE;
        final int dataSizeToCopy = dataEnc.length - COUNTERS_SIZE - PADDING_COUNTER_SIZE - RESPONSE_CODE_RESPONSE_SIZE - signatureLength;

        if (dataSize < dataSizeToCopy) {
          throw new Gsm0348Exception(
                  "Packet recovery failure. Possibly because of unexpected security bytes length. Expected: "
                          + signatureSize);
        }

        packetData = new byte[dataSize];

        System.arraycopy(dataEnc, COUNTERS_SIZE + PADDING_COUNTER_SIZE + RESPONSE_CODE_RESPONSE_SIZE + signatureLength, packetData, 0, dataSizeToCopy);
//				<- End of new code
//				End of modification by Tomas Andersen / Morecom AS 2014.04.08 - TEST CASE: Tomas Andersen Bug #1->
      } else {
        System.arraycopy(data, 2 + COUNTERS_RESPONSE_POSITION, counters, 0, COUNTERS_SIZE);
        paddingCounter = Util.byteToInt(data[2 + PADDING_COUNTER_RESPONSE_POSITION]);
        responseCode = data[RESPONSE_CODE_RESPONSE_POSITION];
        System.arraycopy(data, SIGNATURE_RESPONSE_POSITION, signature, 0, signatureLength);
        final int dataSize = packetLength - headerLength - HEADER_LENGTH_SIZE;
        packetData = new byte[dataSize];
        System.arraycopy(data, headerLength + HEADER_LENGTH_SIZE + PACKET_LENGTH_SIZE, packetData, 0, dataSize);
      }

      if (responsePacketSigning) {
        int addonAmount = 0;
        if (cardProfile.getSecurityBytesType() == SecurityBytesType.WITH_LENGHTS_AND_UDHL) {
          addonAmount = 6;
        } else if (cardProfile.getSecurityBytesType() == SecurityBytesType.WITH_LENGHTS) {
          addonAmount = 3;
        }

        byte[] signData = new byte[addonAmount + TAR_SIZE + PADDING_COUNTER_SIZE + RESPONSE_CODE_RESPONSE_SIZE
            + COUNTERS_SIZE + packetData.length];
        switch (cardProfile.getSecurityBytesType()) {
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
        if (!valid) {
          throw new Gsm0348Exception("Signatures don't match");
        }
      }

      ResponsePacketHeader pacHeader = new ResponsePacketHeader();
      pacHeader.setCounter(counters);
      pacHeader.setPaddingCounter((byte) paddingCounter);
      pacHeader.setResponseStatus(ResponsePacketStatusCoder.encode(responseCode));
      pacHeader.setChecksumSignature(signature);
      pacHeader.setTAR(tar);

      ResponsePacket pac = new ResponsePacket();
      // remove padding from end of packetData
      if (paddingCounter > 0) {
        byte[] packetDataWithoutPadding = new byte[packetData.length-paddingCounter];
        System.arraycopy(packetData, 0, packetDataWithoutPadding, 0, packetData.length
        -paddingCounter);
        packetData = packetDataWithoutPadding;
      }
      pac.setData(packetData);
      pac.setHeader(pacHeader);

      LOGGER.debug("Packet recovered : {}", pac);
      return pac;
    } catch (GeneralSecurityException e) {
      throw new Gsm0348Exception(e);
    }
  }

  @Override
  public byte[] buildResponsePacket(byte[] data, byte[] counter, byte[] cipheringKey, byte[] signatureKey,
                                    ResponsePacketStatus responseStatus) throws PacketBuilderConfigurationException, Gsm0348Exception {
    if (!isConfigured()) {
      throw new PacketBuilderConfigurationException("Not configured");
    }

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Creating response packet.\n\tData: {}\n\tCounter: {}\n\tCipheringKey: {}\n\tSigningKey: {}"
          , Util.toHexString(data)
          , Util.toHexString(counter)
          , Util.toHexString(cipheringKey)
          , Util.toHexString(signatureKey));
    }

    if (responsePacketCiphering && (cipheringKey == null)) {
      throw new PacketBuilderConfigurationException("Ciphering is enabled - ciphering key must be specified");
    }
    if (responsePacketSigning && (signatureKey == null)) {
      throw new PacketBuilderConfigurationException("Signing is enabled - signature key must be specified");
    }
    if (counter == null && usingCounters) {
      throw new PacketBuilderConfigurationException("Counters are null and they are required by configuration");
    }
    if (counter != null && counter.length != COUNTERS_SIZE) {
      throw new PacketBuilderConfigurationException("Counters size mismatch. Current = "
          + (counter != null ? counter.length : "counter == null") + ". Required:" + COUNTERS_SIZE);
    }

    try {
      LOGGER.debug("Signing: {}", responsePacketSigning);
      final int signatureLength = responsePacketSigning ? signatureSize : 0;
      LOGGER.debug("Signature length: {}", signatureLength);
      final int headerLenght = HEADER_LENGTH_SIZE + RESPONSE_HEADER_SIZE_WITHOUT_SIGNATURE + signatureLength;
      LOGGER.debug("Header length (including size byte): {}", headerLenght);

      byte[] signature = new byte[signatureLength];
      byte[] headerData = new byte[headerLenght];
      byte[] dataBytes = (data == null) ? new byte[0] : data;
      byte[] countersBytes = usingCounters ? counter : new byte[COUNTERS_SIZE];
      byte paddingCounter = 0;

      headerData[HEADER_LENGTH_POSITION] = (byte) (headerLenght - HEADER_LENGTH_SIZE);
      LOGGER.debug("Header length value: {}", headerData[HEADER_LENGTH_POSITION]);
      System.arraycopy(cardProfile.getTAR(), 0, headerData, TAR_RESPONSE_POSITION, TAR_SIZE);
      LOGGER.debug("TAR value: {}", Util.toHexArray(Arrays.copyOfRange(headerData, TAR_RESPONSE_POSITION, TAR_RESPONSE_POSITION + TAR_SIZE)));
      System.arraycopy(countersBytes, 0, headerData, COUNTERS_RESPONSE_POSITION, COUNTERS_SIZE);
      LOGGER.debug("COUNTER value: {}",
          Util.toHexArray(Arrays.copyOfRange(headerData, COUNTERS_RESPONSE_POSITION, COUNTERS_RESPONSE_POSITION + COUNTERS_SIZE)));

      if (responsePacketCiphering) {
        final int dataSize = COUNTERS_SIZE + PADDING_COUNTER_SIZE + STATUS_CODE_SIZE + signatureLength + dataBytes.length;
        paddingCounter = (byte) (getPadding(dataSize, cipherBlockSize) & 0xff);
      }
      headerData[PADDING_COUNTER_RESPONSE_POSITION] = paddingCounter;
      LOGGER.debug("Padding counter value: {}", String.format("0x%02X", headerData[PADDING_COUNTER_RESPONSE_POSITION]));

      headerData[STATUS_CODE_RESPONSE_POSITION] = (byte) (responseStatus.ordinal() & (byte) 0xFF);
      LOGGER.debug("Response status code value: {}", String.format("0x%02X", headerData[STATUS_CODE_RESPONSE_POSITION]));

      if (responsePacketSigning) {
        int addonAmount = 0;
        if (cardProfile.getSecurityBytesType() == SecurityBytesType.WITH_LENGHTS_AND_UDHL) {
          addonAmount = 3;
        } else if (cardProfile.getSecurityBytesType() == SecurityBytesType.WITH_LENGHTS) {
          addonAmount = 0;
        }

        byte[] signData = new byte[addonAmount + headerLenght + dataBytes.length - signatureLength + PACKET_LENGTH_SIZE + paddingCounter];
        switch (cardProfile.getSecurityBytesType()) {
          case WITH_LENGHTS_AND_UDHL:
            signData[0] = 0x02;
            signData[1] = 0x71;
            signData[2] = 0x00;
            // System.arraycopy(data, 0, signData, 3, 3);
            break;
          case WITH_LENGHTS:
            // System.arraycopy(data, 0, signData, 0, 3);
            break;
        }
        final int length = dataBytes.length + paddingCounter + headerLenght;
        signData[addonAmount] = (byte) ((length >> 8) & (byte) 0xff);
        signData[addonAmount + 1] = (byte) ((length & (byte) 0xff));
        System.arraycopy(headerData, 0, signData, addonAmount + 2, headerLenght - signatureLength);
        System.arraycopy(dataBytes, 0, signData, headerLenght - signatureLength + addonAmount + 2, dataBytes.length);
        LOGGER.debug("Signing data: {} length: {} ({})", Util.toHexString(signData), signData.length, signatureAlgorithmName);
        signature = SignatureManager.sign(signatureAlgorithmName, signatureKey, signData);
      }
      if (signature.length != signatureLength) {
        throw new Gsm0348Exception("The generated signature length doesn't match the expected length");
      }
      System.arraycopy(signature, 0, headerData, SIGNATURE_RESPONSE_POSITION - PACKET_LENGTH_SIZE, signatureLength);
      LOGGER.debug("Signature value: {} length:{}", Util.toHexString(signature), signature.length);

      if (responsePacketCiphering) {
        LOGGER.trace("Ciphering response");
        byte[] cipherData = new byte[COUNTERS_SIZE + PADDING_COUNTER_SIZE + STATUS_CODE_SIZE + signatureLength + dataBytes.length];
        System.arraycopy(countersBytes, 0, cipherData, 0, COUNTERS_SIZE);
        cipherData[COUNTERS_SIZE] = paddingCounter;
        cipherData[COUNTERS_SIZE + 1] = (byte) (responseStatus.ordinal() & (byte) 0xFF);
        System.arraycopy(signature, 0, cipherData, 7, signatureLength);
        System.arraycopy(dataBytes, 0, cipherData, 7 + signatureLength, dataBytes.length);

        LOGGER.debug("Ciphering data: {} length: {}", Util.toHexString(cipherData), cipherData.length);
        byte[] cipheredData = CipheringManager.encipher(cipheringAlgorithmName, cipheringKey, cipherData, countersBytes);
        LOGGER.debug("Ciphered data: {} length: {}", Util.toHexString(cipheredData), cipheredData.length);

        final byte[] headerCiphered = new byte[4];
        System.arraycopy(headerData, 0, headerCiphered, 0, headerCiphered.length);
        LOGGER.debug("Ciphered response header data: {} length: {}", Util.toHexString(headerCiphered), headerCiphered.length);
        byte[] result = createPacket(headerCiphered, cipheredData);
        LOGGER.debug("Ciphered response packet created: {} length: {}", Util.toHexString(result), result.length);
        return result;
      }
      LOGGER.debug("Clear response header data: {} length: {}", Util.toHexString(headerData), headerData.length);
      byte[] result = createPacket(headerData, dataBytes);
      LOGGER.debug("Clear response packet created: {} length: {}", Util.toHexString(result), result.length);
      return result;
    } catch (GeneralSecurityException e) {
      throw new Gsm0348Exception(e);
    }
  }

  @Override
  public CommandPacket recoverCommandPacket(byte[] data, byte[] cipheringKey, byte[] signatureKey) throws Gsm0348Exception {
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Recovering command packet.\n\tData: {}\n\tCipheringKey: {}\n\tSigningKey: {}",
          Util.toHexArray(data),
          Util.toHexArray(cipheringKey),
          Util.toHexArray(signatureKey));
    }

    if (data == null) {
      throw new IllegalArgumentException("Packet data cannot be null");
    }

    final int packetLength = (Util.byteToInt(data[0]) >> 8) + Util.byteToInt(data[1]);
    if (data.length - PACKET_LENGTH_SIZE != packetLength) {
      throw new Gsm0348Exception(
          "Length of raw data doesn't match packet length. Expected " + packetLength + " but found " + (data.length - PACKET_LENGTH_SIZE));
    }

    final int headerLength = Util.byteToInt(data[PACKET_LENGTH_SIZE + HEADER_LENGTH_POSITION]);
    final byte[] header = new byte[headerLength];
    System.arraycopy(data, PACKET_LENGTH_SIZE, header, 0, headerLength);
    LOGGER.debug("Header[{}]: {}", header.length, Util.toHexArray(header));

    final byte[] spiBytes = new byte[SPI_SIZE];
    System.arraycopy(header, SPI_POSITION, spiBytes, 0, SPI_SIZE);
    LOGGER.debug("SPI: {}", Util.toHexArray(spiBytes));
    final SPI spi = getSPI(spiBytes);

    final byte[] kicBytes = new byte[KIC_SIZE];
    System.arraycopy(header, KIC_POSITION, kicBytes, 0, KIC_SIZE);
    LOGGER.debug("KIC: {}", Util.toHexArray(kicBytes));
    final KIC kic = KICCoder.encode(kicBytes[0]);

    final byte[] kidBytes = new byte[KID_SIZE];
    System.arraycopy(header, KID_POSITION, kidBytes, 0, KID_SIZE);
    LOGGER.debug("KID: {}", Util.toHexArray(kidBytes));
    final KID kid = KIDCoder.encode(spi.getCommandSPI().getCertificationMode(), kidBytes[0]);

    final byte[] tar = new byte[TAR_SIZE];
    System.arraycopy(header, TAR_POSITION, tar, 0, TAR_SIZE);
    LOGGER.debug("TAR: {}", Util.toHexArray(tar));

    commandPacketSigning = spi.getCommandSPI().getCertificationMode() != CertificationMode.NO_SECURITY;
    commandPacketCiphering = spi.getCommandSPI().isCiphered();

    cardProfile.setSPI(spi);
    cardProfile.setKIC(kic);
    cardProfile.setKID(kid);

    if (commandPacketCiphering) {
      setCipheringAlgorithmName(cardProfile);
    }
    if (commandPacketSigning) {
      setSigningAlgorithmName(cardProfile);
    }

    final byte[] counters = new byte[COUNTERS_SIZE];
    final int signatureLength = commandPacketSigning ? signatureSize : 0;

    if (commandPacketCiphering && (cipheringKey == null || cipheringKey.length == 0)) {
      throw new PacketBuilderConfigurationException(
              "Ciphering is enabled - ciphering key must be specified. Provided: "
                      + ((cipheringKey.length == 0) ? "empty" : Util.toHexArray(cipheringKey)));
    }
    if (commandPacketSigning && (signatureKey == null || signatureKey.length == 0)) {
      throw new PacketBuilderConfigurationException(
              "Signing is enabled - signature key must be specified. Provided: "
                      + ((signatureKey.length == 0) ? "empty" : Util.toHexArray(signatureKey)));
    }

    if (data.length < MINIMUM_COMMAND_PACKET_SIZE + signatureLength) {
      String message = "rawdata too small to be command packet. Expected to be >= "
          + (MINIMUM_COMMAND_PACKET_SIZE + signatureLength) + ", but found " + data.length;
      if (data.length >= MINIMUM_COMMAND_PACKET_SIZE) {
        message += ". It can be caused by incorrect profile(SPI value). Check SPI!";
        LOGGER.warn("Packet received(raw): {}", Util.toHexArray(data));
      }
      throw new Gsm0348Exception(message);
    }

    final byte[] signature = new byte[signatureLength];
    LOGGER.debug("Signature length: {}", signatureLength);

    int paddingCounter;
    byte[] packetData;
    try {
      if (commandPacketCiphering) {
        byte[] dataDec = CipheringManager.decipher(cipheringAlgorithmName, cipheringKey,
            Arrays.copyOfRange(data, PACKET_LENGTH_SIZE + HEADER_LENGTH_SIZE + TAR_SIZE + SPI_SIZE + KIC_SIZE + KID_SIZE, data.length));
        LOGGER.info("Decrypted: {}", Util.toHexArray(dataDec));

        System.arraycopy(dataDec, 0, counters, 0, COUNTERS_SIZE);
        LOGGER.debug("Counters[{}]: {}", counters.length, Util.toHexArray(counters));
        paddingCounter = Util.byteToInt(dataDec[COUNTERS_SIZE]);
        LOGGER.debug("Padding counter: {}", paddingCounter);

        System.arraycopy(dataDec, COUNTERS_SIZE + 1, signature, 0, signatureLength);
        LOGGER.debug("Signature[{}]: {}", signature.length, Util.toHexArray(signature));

        final int dataSize = packetLength - headerLength - HEADER_LENGTH_SIZE;
        final int dataSizeToCopy = dataDec.length - COUNTERS_SIZE - PADDING_COUNTER_SIZE - signatureLength;

        packetData = new byte[dataSize];
        System.arraycopy(dataDec, COUNTERS_SIZE + PADDING_COUNTER_SIZE + signatureLength, packetData, 0, dataSizeToCopy);
      } else {
        System.arraycopy(data, PACKET_LENGTH_SIZE + COUNTERS_POSITION, counters, 0, COUNTERS_SIZE);
        LOGGER.debug("Counters[{}]: {}", counters.length, Util.toHexArray(counters));
        paddingCounter = Util.byteToInt(data[PACKET_LENGTH_SIZE + PADDING_COUNTER_POSITION]);
        LOGGER.debug("Padding counter: {}", paddingCounter);
        if (paddingCounter != 0) {
          throw new Gsm0348Exception(
              "Command packet ciphering is off but padding counter is not 0. So it can be corrupted packet or configuration doesn't match provided data");
        }

        System.arraycopy(data, PACKET_LENGTH_SIZE + SIGNATURE_POSITION, signature, 0, signatureLength);
        LOGGER.debug("Signature[{}]: {}", signature.length, Util.toHexArray(signature));
        final int dataSize = packetLength - headerLength - HEADER_LENGTH_SIZE;
        packetData = new byte[dataSize];
        System.arraycopy(data, headerLength + HEADER_LENGTH_SIZE + PACKET_LENGTH_SIZE, packetData, 0, dataSize);
      }
      LOGGER.debug("PacketData[{}]: {}", packetData.length, Util.toHexArray(packetData));

      if (commandPacketSigning) {
//        int addonAmount = 0;
//        LOGGER.info("SecurityBytesType: {}", cardProfile.getSecurityBytesType());
//        if (cardProfile.getSecurityBytesType() == SecurityBytesType.WITH_LENGHTS_AND_UDHL) {
//          addonAmount = 6;
//        } else if (cardProfile.getSecurityBytesType() == SecurityBytesType.WITH_LENGHTS) {
//          addonAmount = 3;
//        }
        int addonAmount = PACKET_LENGTH_SIZE + HEADER_LENGTH_SIZE;
        byte[] signData = new byte[addonAmount + HEADER_SIZE_WITHOUT_SIGNATURE + packetData.length];

//        switch (cardProfile.getSecurityBytesType()) {
//          case WITH_LENGHTS_AND_UDHL:
//            signData[0] = 0x02;
//            signData[1] = 0x70;
//            signData[2] = 0x00;
//            System.arraycopy(data, 0, signData, 3, 3);
//            break;
//          case WITH_LENGHTS:
//            System.arraycopy(data, 0, signData, 0, 3);
//            break;
//          case NORMAL:
//            break;
//        }
        System.arraycopy(data, 0, signData, 0, addonAmount + SPI_SIZE + KIC_SIZE + KID_SIZE + TAR_SIZE);
        System.arraycopy(counters, 0, signData, addonAmount + SPI_SIZE + KIC_SIZE + KID_SIZE + TAR_SIZE, COUNTERS_SIZE);
        signData[addonAmount + SPI_SIZE + KIC_SIZE + KID_SIZE + TAR_SIZE + COUNTERS_SIZE] = (byte) paddingCounter;
        System.arraycopy(packetData, 0, signData, addonAmount + HEADER_SIZE_WITHOUT_SIGNATURE,
            packetData.length);

        LOGGER.debug("Verify[{}]: {}", signData.length, Util.toHexArray(signData));
        final boolean valid = SignatureManager.verify(signatureAlgorithmName, signatureKey, signData, signature);
        if (!valid) {
          throw new Gsm0348Exception("Signatures don't match");
        } else {
          LOGGER.debug("Signatures do match");
        }
      }

      final CommandPacketHeader pacHeader = new CommandPacketHeader();
      pacHeader.setCounter(counters);
      pacHeader.setPaddingCounter((byte) paddingCounter);
      pacHeader.setKIC(kic);
      pacHeader.setKID(kid);
      pacHeader.setSPI(spi);
      pacHeader.setChecksumSignature(signature);
      pacHeader.setTAR(tar);

      final CommandPacket pac = new CommandPacket();
      pac.setData(packetData);
      pac.setHeader(pacHeader);
      LOGGER.debug("Command Packet recovered: {}", pac);
      return pac;
    } catch (GeneralSecurityException e) {
      throw new Gsm0348Exception(e);
    }
  }

  private byte[] createPacket(final byte[] first, final byte[] second) {
    byte[] result = new byte[PACKET_LENGTH_SIZE + first.length + second.length];
    result[0] = (byte) (((first.length + second.length) >> 8) & (byte) 0xff);
    result[1] = (byte) (((first.length + second.length) & (byte) 0xff));
    System.arraycopy(first, 0, result, PACKET_LENGTH_SIZE, first.length);
    System.arraycopy(second, 0, result, first.length + PACKET_LENGTH_SIZE, second.length);
    return result;
  }

  private int getPadding(final int dataSize, final int blockSize) {
    final int remainder = dataSize % blockSize;
    if (remainder != 0) {
      return (blockSize - remainder);
    }
    return 0;
  }

}
