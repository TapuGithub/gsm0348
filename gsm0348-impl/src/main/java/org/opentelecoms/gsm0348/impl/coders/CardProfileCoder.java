package org.opentelecoms.gsm0348.impl.coders;

import java.util.Arrays;

import org.opentelecoms.gsm0348.api.Util;
import org.opentelecoms.gsm0348.api.model.CardProfile;
import org.opentelecoms.gsm0348.api.model.CertificationMode;
import org.opentelecoms.gsm0348.api.model.KIC;
import org.opentelecoms.gsm0348.api.model.KID;
import org.opentelecoms.gsm0348.api.model.SPI;
import org.opentelecoms.gsm0348.impl.CodingException;
import org.opentelecoms.gsm0348.impl.crypto.SignatureManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class provides methods for converting row bytes array to {@linkplain CardProfile} and backside.
 *
 * @author Vasily Avilov
 */
public class CardProfileCoder {

  private static final Logger LOGGER = LoggerFactory.getLogger(CardProfileCoder.class);

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

  private static final int MINIMUM_COMMAND_PACKET_SIZE = 16;
  private static final int MINIMUM_RESPONSE_PACKET_SIZE = 13;

  private static final int HEADER_SIZE_WITOUT_SIGNATURE = SPI_SIZE + KIC_SIZE + KID_SIZE + TAR_SIZE + COUNTERS_SIZE
      + PADDING_COUNTER_SIZE;

  private static final int HEADER_SIZE_UNCRIPTED = HEADER_LENGHT_SIZE + SPI_SIZE + KIC_SIZE + KID_SIZE + TAR_SIZE;

  /**
   * Build {@linkplain CardProfile} from row byte array
   *
   * @param datarow - the message heater {@linkplain byte[]} row.
   * @return CardProfile
   * @throws NullPointerException if <strong>datarow</strong> parameter is null.
   * @throws CodingException      if configuration is in inconsistent state.
   */
  public static CardProfile encode(byte[] datarow) throws CodingException {

    if (datarow == null) {
      throw new NullPointerException();
    }

    if (datarow.length < 7) {
      throw new CodingException("Incorrect header size");
    }

    CardProfile newCardProfile = new CardProfile();

    // cardProfile.setSecurityBytesType(SecurityBytesType.WITH_LENGHTS);

    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode(datarow[SPI_POSITION - 1]));
    spi.setResponseSPI(ResponseSPICoder.encode(datarow[SPI_POSITION]));

    LOGGER.debug("SPI value: {}", spi.toString());

    KIC kic = KICCoder.encode(datarow[KIC_POSITION - 1]);
    LOGGER.debug("KIC value: {}", kic);
    KID kid = KIDCoder.encode(spi.getCommandSPI().getCertificationMode(), datarow[KID_POSITION - 1]);
    LOGGER.debug("KID value: {}", kid);

    newCardProfile.setTAR(Arrays.copyOfRange(datarow, TAR_POSITION - 1, TAR_POSITION - 1 + TAR_SIZE));

    LOGGER.debug("TAR value: {}", Util.toHexArray(newCardProfile.getTAR()));

    newCardProfile.setSPI(spi);
    newCardProfile.setKIC(kic);
    newCardProfile.setKID(kid);

    // The initial chaining value for CBC modes shall be zero.

    switch (kic.getAlgorithmImplementation()) {
      case PROPRIETARY_IMPLEMENTATIONS:
      case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
        break;
      case DES:
        switch (kic.getCipheringAlgorithmMode()) {
          case DES_CBC:
            newCardProfile.setCipheringAlgorithm("DES/CBC/ZeroBytePadding");
            break;

          case DES_ECB:
            newCardProfile.setCipheringAlgorithm("DES/ECB/ZeroBytePadding");
            break;

          case TRIPLE_DES_CBC_2_KEYS:
          case TRIPLE_DES_CBC_3_KEYS:
            newCardProfile.setCipheringAlgorithm("DESede/CBC/ZeroBytePadding");
            break;

          default:
        }
        break;

      case AES:
        // AES shall be used together with counter settings (b5 and b4 of the first octet of SPI) 10 or 11.
        switch (kic.getCipheringAlgorithmMode()) {
          case AES_CBC:
            newCardProfile.setCipheringAlgorithm("AES/CBC/ZeroBytePadding");
            break;
          default:
        }
        break;

      default:
    }


    if (!spi.getCommandSPI().getCertificationMode().equals(CertificationMode.NO_SECURITY)) {
      switch (kid.getAlgorithmImplementation()) {
        case CRC:
          switch (kid.getCertificationAlgorithmMode()) {
            case CRC_16:
              newCardProfile.setSignatureAlgorithm("CRC16");
              break;
            case CRC_32:
              newCardProfile.setSignatureAlgorithm("CRC32");
              break;
          }
        case PROPRIETARY_IMPLEMENTATIONS:
        case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
          break;
        case DES:
          switch (kid.getCertificationAlgorithmMode()) {
            case DES_CBC:
              newCardProfile.setSignatureAlgorithm(SignatureManager.DES_MAC8_ISO9797_M1);
              break;

            case RESERVED:
              break;

            case TRIPLE_DES_CBC_2_KEYS:
            case TRIPLE_DES_CBC_3_KEYS:
              newCardProfile.setSignatureAlgorithm("DESEDEMAC64");
              break;

            default:
          }
          break;
        case AES:
          newCardProfile.setSignatureAlgorithm("AESCMAC");
          break;
      }
    }
    return newCardProfile;
  }

  /**
   * Build {@linkplain byte[]} from {@linkplain CardProfile}
   *
   * @param profile - a card profile {@linkplain CardProfile}.
   * @return byte[]
   * @throws NullPointerException if <strong>profile</strong> parameter is null.
   * @throws CodingException      if configuration is in inconsistent state.
   */
  public static byte[] decode(CardProfile profile) throws CodingException {

    if (profile == null) {
      throw new IllegalArgumentException("The profile argument cannot be null");
    }

    byte[] headerData = new byte[7];

    headerData[0] = CommandSPICoder.decode(profile.getSPI().getCommandSPI());
    headerData[1] = ResponseSPICoder.decode(profile.getSPI().getResponseSPI());
    LOGGER.debug("SPI value: {}", String.format("%1$#x %2$#x", headerData[0], headerData[1]));

    headerData[KIC_POSITION - 1] = KICCoder.decode(profile.getKIC());
    LOGGER.debug("KIC value: {}", Util.toHex(headerData[KIC_POSITION - 1]));
    headerData[KID_POSITION - 1] = KIDCoder.decode(profile.getKID());
    LOGGER.debug("KID value: {}", Util.toHex(headerData[KID_POSITION - 1]));
    System.arraycopy(profile.getTAR(), 0, headerData, TAR_POSITION - 1, TAR_SIZE);
    LOGGER.debug("TAR value: {}", Util.toHexArray(Arrays.copyOfRange(headerData, TAR_POSITION - 1, TAR_POSITION - 1 + TAR_SIZE)));

    return headerData;
  }
}
