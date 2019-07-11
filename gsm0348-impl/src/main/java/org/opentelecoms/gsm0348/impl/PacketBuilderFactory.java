package org.opentelecoms.gsm0348.impl;

import org.opentelecoms.gsm0348.api.PacketBuilder;
import org.opentelecoms.gsm0348.api.PacketBuilderConfigurationException;
import org.opentelecoms.gsm0348.api.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Trivial {@linkplain PacketBuilder} factory. It creates new
 * {@linkplain PacketBuilder} for each {@linkplain CardProfile}.
 *
 * @author Victor Platov
 */
public class PacketBuilderFactory {
  private static final Logger LOGGER = LoggerFactory.getLogger(PacketBuilderFactory.class);

  private PacketBuilderFactory() {
  }

  public static PacketBuilder getInstance(CardProfile cardProfile) throws PacketBuilderConfigurationException {
    LOGGER.debug("Creating new PacketBuilder for {}", cardProfile);
    return new PacketBuilderImpl(cardProfile);
  }

  /**
   * Creates a default instance with no security applied.
   * <p>
   *     Useful for recovering packets with {@link PacketBuilder#recoverCommandPacket(byte[], byte[], byte[])}.
   * </p>
   * @return the created packet builder.
   */
  public static PacketBuilder getInstance() {
    CardProfile cardProfile = new CardProfile();
    cardProfile.setSecurityBytesType(SecurityBytesType.WITH_LENGHTS_AND_UDHL);
    cardProfile.setTAR(new byte[]{0,0,0});
    KIC kic = new KIC();
    kic.setAlgorithmImplementation(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES);
    kic.setCipheringAlgorithmMode(CipheringAlgorithmMode.DES_CBC);
    kic.setKeysetID((byte) 0);
    cardProfile.setKIC(kic);

    KID kid = new KID();
    kid.setAlgorithmImplementation(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES);
    kid.setCertificationAlgorithmMode(CertificationAlgorithmMode.DES_CBC);
    kid.setKeysetID((byte) 0);
    cardProfile.setKID(kid);

    SPI spi = new SPI();
    CommandSPI commandSPI = new CommandSPI();
    commandSPI.setCertificationMode(CertificationMode.NO_SECURITY);
    commandSPI.setCiphered(false);
    commandSPI.setSynchroCounterMode(SynchroCounterMode.COUNTER_NO_REPLAY_NO_CHECK);
    spi.setCommandSPI(commandSPI);

    ResponseSPI responseSPI = new ResponseSPI();
    responseSPI.setCiphered(false);
    responseSPI.setPoRCertificateMode(CertificationMode.NO_SECURITY);
    responseSPI.setPoRMode(PoRMode.NO_REPLY);
    responseSPI.setPoRProtocol(PoRProtocol.SMS_SUBMIT);
    spi.setResponseSPI(responseSPI);
    cardProfile.setSPI(spi);
    try {
      return getInstance(cardProfile);
    } catch (PacketBuilderConfigurationException e) {
      throw new RuntimeException("Could no", e);
    }
  }

}
