import static org.opentelecoms.gsm0348.api.model.ResponsePacketStatus.POR_OK;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opentelecoms.gsm0348.api.PacketBuilder;
import org.opentelecoms.gsm0348.api.Util;
import org.opentelecoms.gsm0348.api.model.AlgorithmImplementation;
import org.opentelecoms.gsm0348.api.model.CardProfile;
import org.opentelecoms.gsm0348.api.model.CertificationAlgorithmMode;
import org.opentelecoms.gsm0348.api.model.CertificationMode;
import org.opentelecoms.gsm0348.api.model.CipheringAlgorithmMode;
import org.opentelecoms.gsm0348.api.model.CommandSPI;
import org.opentelecoms.gsm0348.api.model.KIC;
import org.opentelecoms.gsm0348.api.model.KID;
import org.opentelecoms.gsm0348.api.model.PoRMode;
import org.opentelecoms.gsm0348.api.model.PoRProtocol;
import org.opentelecoms.gsm0348.api.model.ResponsePacket;
import org.opentelecoms.gsm0348.api.model.ResponsePacketStatus;
import org.opentelecoms.gsm0348.api.model.ResponseSPI;
import org.opentelecoms.gsm0348.api.model.SPI;
import org.opentelecoms.gsm0348.api.model.SecurityBytesType;
import org.opentelecoms.gsm0348.api.model.SynchroCounterMode;
import org.opentelecoms.gsm0348.impl.CodingException;
import org.opentelecoms.gsm0348.impl.PacketBuilderFactory;
import org.opentelecoms.gsm0348.impl.coders.CommandSPICoder;
import org.opentelecoms.gsm0348.impl.coders.KICCoder;
import org.opentelecoms.gsm0348.impl.coders.KIDCoder;
import org.opentelecoms.gsm0348.impl.coders.ResponseSPICoder;
import org.opentelecoms.gsm0348.impl.crypto.SignatureManager;
import org.slf4j.impl.SimpleLogger;

public class Gsm0348Test {
  private PacketBuilder packetBuilder;
  private byte[] cipheringKey;
  private byte[] signatureKey;

  private static CardProfile createProfile() {
    CardProfile cardProfile = new CardProfile();
    cardProfile.setCipheringAlgorithm("");
    cardProfile.setSignatureAlgorithm("");
    cardProfile.setSecurityBytesType(SecurityBytesType.WITH_LENGHTS_AND_UDHL);
    cardProfile.setTAR(new byte[]{ (byte) 0xb0, 0x00, 0x10 });

    KIC kic = new KIC();
    kic.setAlgorithmImplementation(AlgorithmImplementation.DES);
    kic.setCipheringAlgorithmMode(CipheringAlgorithmMode.DES_CBC);
    kic.setKeysetID((byte) 1);
    cardProfile.setKIC(kic);

    KID kid = new KID();
    kid.setAlgorithmImplementation(AlgorithmImplementation.DES);
    kid.setCertificationAlgorithmMode(CertificationAlgorithmMode.DES_CBC);
    kid.setKeysetID((byte) 1);
    cardProfile.setKID(kid);

    SPI spi = new SPI();
    CommandSPI commandSPI = new CommandSPI();
    commandSPI.setCertificationMode(CertificationMode.CC);
    commandSPI.setCiphered(true);
    commandSPI.setSynchroCounterMode(SynchroCounterMode.NO_COUNTER);
    spi.setCommandSPI(commandSPI);

    ResponseSPI responseSPI = new ResponseSPI();
    responseSPI.setCiphered(false);
    responseSPI.setPoRCertificateMode(CertificationMode.NO_SECURITY);
    responseSPI.setPoRMode(PoRMode.REPLY_ALWAYS);
    responseSPI.setPoRProtocol(PoRProtocol.SMS_DELIVER_REPORT);
    spi.setResponseSPI(responseSPI);

    cardProfile.setSPI(spi);

    return cardProfile;
  }

  private static CardProfile createProfileAes(final SecurityBytesType securityBytesType, final boolean cipher,
                                              final SynchroCounterMode synchroCounterMode) throws CodingException {
    CardProfile cardProfile = new CardProfile();
    cardProfile.setCipheringAlgorithm("");
    cardProfile.setSignatureAlgorithm("AES_CMAC_64");
    cardProfile.setSecurityBytesType(securityBytesType);
    cardProfile.setTAR(new byte[]{ (byte) 0x00, 0x00, 0x01 });

    KIC kic = new KIC();
    kic.setAlgorithmImplementation(AlgorithmImplementation.AES);
    kic.setCipheringAlgorithmMode(CipheringAlgorithmMode.AES_CBC);
    kic.setKeysetID((byte) 1);
    cardProfile.setKIC(kic);

    KID kid = new KID();
    kid.setAlgorithmImplementation(AlgorithmImplementation.AES);
    kid.setCertificationAlgorithmMode(CertificationAlgorithmMode.AES_CMAC);
    kid.setKeysetID((byte) 1);
    cardProfile.setKID(kid);

    SPI spi = new SPI();
    CommandSPI commandSPI = new CommandSPI();
    commandSPI.setCertificationMode(CertificationMode.CC);
    commandSPI.setCiphered(cipher);
    commandSPI.setSynchroCounterMode(synchroCounterMode);
    spi.setCommandSPI(commandSPI);

    ResponseSPI responseSPI = new ResponseSPI();
    responseSPI.setCiphered(cipher);
    responseSPI.setPoRCertificateMode(CertificationMode.CC);
    responseSPI.setPoRMode(PoRMode.REPLY_ALWAYS);
    responseSPI.setPoRProtocol(PoRProtocol.SMS_SUBMIT);
    spi.setResponseSPI(responseSPI);
    cardProfile.setSPI(spi);

    cardProfile.setSPI(spi);

    return cardProfile;
  }

  public static void main(String[] args) throws Exception {
    System.setProperty(SimpleLogger.DEFAULT_LOG_LEVEL_KEY, "debug");
    System.setProperty("java.util.logging.ConsoleHandler.level", "FINEST");
    /*
     * Adding security provider - it will do all security job
     */
    Security.addProvider(new BouncyCastleProvider());

    /*
     * Creating card profile - for each service(with unique TAR)
     */
    CardProfile cardProfile = createProfile();

    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    /*
     * Data to be sent to applet. Commonly it is a APDU command for Remote File Management Applet.
     * Or RAM Applet.
     */
    byte[] data = new byte[]{ 1, 2, 3, 4, 5 };
    byte[] counters = new byte[]{ 0, 0, 0, 0, 2 };

    /*
     * Security keys. Mostly produced from master keys. See ICCIDKeyGenerator.
     */
    byte[] cipheringKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };
    byte[] signatureKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };

    byte[] packet = packetBuilder.buildCommandPacket(data, counters, cipheringKey, signatureKey);

    System.out.println(Util.toHexArray(packet));

    byte[] responsePacketBytes = new byte[]{ 0x00, 0x0E, 0x0A, (byte) 0xB0, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x6E, 0x00 };
    ResponsePacket responsePacket = packetBuilder.recoverResponsePacket(responsePacketBytes, cipheringKey, signatureKey);

    System.out.println(responsePacket);
  }

  @Before
  public void setup() throws Exception {
    System.setProperty(SimpleLogger.DEFAULT_LOG_LEVEL_KEY, "debug");
    System.setProperty("java.util.logging.ConsoleHandler.level", "FINEST");
    /*
     * Adding security provider - it will do all security job
     */
    Security.addProvider(new BouncyCastleProvider());

    /*
     * Creating card profile - for each service(with unique TAR)
     */
    CardProfile cardProfile = createProfile();

    packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    cipheringKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };
    signatureKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };
  }

  @Test
  public void should_build_command_packet_no_security() throws Exception {
    byte[] data = new byte[]{ (byte) 0xaa, (byte) 0xbb };
    byte[] tar = new byte[]{ 0x01, 0x02, 0x03 };
    CardProfile cardProfile = new CardProfile();
    SPI spi = new SPI();
    // No RC, CC or DS, No Ciphering
    spi.setCommandSPI(CommandSPICoder.encode((byte) 0x00));
    spi.setResponseSPI(ResponseSPICoder.encode((byte) 0x22));
    cardProfile.setSPI(spi);
    cardProfile.setKIC(KICCoder.encode((byte) 0x00));
    cardProfile.setKID(KIDCoder.encode(CertificationMode.NO_SECURITY, (byte) 0x00));
    cardProfile.setSecurityBytesType(SecurityBytesType.WITH_LENGHTS_AND_UDHL);
    cardProfile.setTAR(tar);
    cardProfile.setSignatureAlgorithm(SignatureManager.AES_CMAC_64);
    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);
    byte[] commandBytes = packetBuilder.buildCommandPacket(data, null, null, null);

    System.out.println(Util.toHexString(commandBytes));

    Assert.assertArrayEquals(
        new byte[]{ (byte) 0x00, (byte) 0x10, (byte) 0x0d, (byte) 0x00, (byte) 0x22, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0x02, (byte) 0x03, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xaa, (byte) 0xbb },
        commandBytes);
  }

  @Test
  public void should_build_command_packet_aes() throws Exception {
    byte[] data = new byte[]{ (byte) 0xAA, (byte) 0xBB };
    byte[] counter = new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 };
    byte[] tar = new byte[]{ 0x01, 0x02, 0x03 };
    CardProfile cardProfile = new CardProfile();
    SPI spi = new SPI();
    spi.setCommandSPI(CommandSPICoder.encode((byte) 0x06));
    spi.setResponseSPI(ResponseSPICoder.encode((byte) 0x21));
    cardProfile.setSPI(spi);
    cardProfile.setKIC(KICCoder.encode((byte) 0x12));
    cardProfile.setKID(KIDCoder.encode(CertificationMode.CC, (byte) 0x12));
    cardProfile.setSecurityBytesType(SecurityBytesType.WITH_LENGHTS_AND_UDHL);
    cardProfile.setTAR(tar);
    cardProfile.setSignatureAlgorithm(SignatureManager.AES_CMAC_64);
    PacketBuilder packetBuilder = PacketBuilderFactory.getInstance(cardProfile);
    byte[] cipheringKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
    byte[] signatureKey = new byte[]{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
    byte[] commandBytes = packetBuilder.buildCommandPacket(data, counter, cipheringKey, signatureKey);

    Assert.assertArrayEquals(
        new byte[]{ (byte) 0x00, (byte) 0x18, (byte) 0x15, (byte) 0x06, (byte) 0x21, (byte) 0x12, (byte) 0x12, (byte) 0x01,
            (byte) 0x02, (byte) 0x03, (byte) 0x48, (byte) 0x14, (byte) 0xCE, (byte) 0x84, (byte) 0xCB, (byte) 0xDE,
            (byte) 0xBC, (byte) 0x1A, (byte) 0x0D, (byte) 0xF2, (byte) 0x0A, (byte) 0x5E, (byte) 0xE2, (byte) 0x0E,
            (byte) 0x74, (byte) 0xC6 },
        commandBytes);
  }

  @Test
  public void should_recover_response_packet() throws Exception {
    byte[] responsePacketBytes = new byte[]{ 0x00, 0x0E, 0x0A, (byte) 0xB0, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x6E, 0x00 };
    ResponsePacket responsePacket = packetBuilder.recoverResponsePacket(responsePacketBytes, cipheringKey, signatureKey);

    Assert.assertEquals(ResponsePacketStatus.POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0xB0, 0x00, 0x10 }, responsePacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x01 }, responsePacket.getHeader().getCounter());
    Assert.assertEquals(0x00, responsePacket.getHeader().getPaddingCounter());
    Assert.assertArrayEquals(new byte[]{ 0x01, 0x6E, 0x00 }, responsePacket.getData());
  }

  @Test
  public void should_recover_response_packet_with_extra_data() throws Exception {
    // 027100000E0AB0011F000000000100000A9000
    byte[] responsePacketBytes = Hex.decode("000E0AB0011F000000000100000A9000");
    ResponsePacket responsePacket = packetBuilder.recoverResponsePacket(responsePacketBytes, cipheringKey, signatureKey);

    Assert.assertEquals(ResponsePacketStatus.POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0xB0, 0x01, 0x1F }, responsePacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x01 }, responsePacket.getHeader().getCounter());
    Assert.assertEquals(0x00, responsePacket.getHeader().getPaddingCounter());
    Assert.assertArrayEquals(new byte[]{ 0x0A, (byte) 0x90, 0x00 }, responsePacket.getData());
  }

  @Test
  public void should_build_response_packet() throws Exception {
    byte[] data = new byte[]{ (byte) 0x90, (byte) 0x00 };
    //byte[] counter = new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05 };
    byte[] responsePacketBytes = packetBuilder.buildResponsePacket(data, null, cipheringKey, signatureKey, ResponsePacketStatus.CIPHERING_ERROR);

    Assert.assertArrayEquals(new byte[]{ (byte) 0x00, 0x0D, 0x0A, (byte) 0xB0, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, (byte) 0x90, 0x00 },
        responsePacketBytes);
  }

  @Test
  public void should_build_response_packet_cc_aes_cmac_64_with_lengths_and_udhl() throws Exception {
    CardProfile cardProfile = createProfileAes(SecurityBytesType.WITH_LENGHTS_AND_UDHL, false, SynchroCounterMode.NO_COUNTER);

    // The AES signature key
    final byte[] signatureKey = new byte[]{ (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16 };

    packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    byte[] data = new byte[]{ (byte) 0xab, (byte) 0x07, (byte) 0x80, (byte) 0x01, (byte) 0x01, (byte) 0x23, (byte) 0x02, (byte) 0x90, (byte) 0x00 };
    byte[] counter = new byte[]{ (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
    byte[] responsePacketBytes = packetBuilder.buildResponsePacket(data, counter, null, signatureKey, ResponsePacketStatus.POR_OK);

    Assert.assertArrayEquals(
        new byte[]{ (byte) 0x00, (byte) 0x1c, (byte) 0x12,
            (byte) 0x00, (byte) 0x00, (byte) 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00,
            (byte) 0x00,
            (byte) 0x00,
            (byte) 0xf5, (byte) 0xab, (byte) 0x90, (byte) 0xfe, (byte) 0x3a, (byte) 0xab, (byte) 0xb6, (byte) 0xc3,
            (byte) 0xab, (byte) 0x07, (byte) 0x80, (byte) 0x01, (byte) 0x01, (byte) 0x23, (byte) 0x02, (byte) 0x90, (byte) 0x00 },
        responsePacketBytes);
  }

  @Test
  public void should_recover_response_packet_cc_aes_cmac_64_with_lengths_and_udhl() throws Exception {
    CardProfile cardProfile = createProfileAes(SecurityBytesType.WITH_LENGHTS_AND_UDHL, false, SynchroCounterMode.NO_COUNTER);
    // The AES signature key
    final byte[] signatureKey = new byte[]{ (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16 };
    packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    byte[] responsePacketBytes = Hex.decode("001C1200000100000000000000F5AB90FE3AABB6C3AB0780010123029000");
    ResponsePacket responsePacket = packetBuilder.recoverResponsePacket(responsePacketBytes, null, signatureKey);

    Assert.assertEquals(ResponsePacketStatus.POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x00, 0x00, 0x01 }, responsePacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 }, responsePacket.getHeader().getCounter());
    Assert.assertEquals(0x00, responsePacket.getHeader().getPaddingCounter());
    Assert.assertEquals(POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0xab, (byte) 0x07, (byte) 0x80, (byte) 0x01, (byte) 0x01, (byte) 0x23, (byte) 0x02, (byte) 0x90, (byte) 0x00 },
        responsePacket.getData());
  }

  @Test
  public void should_build_response_packet_cc_aes_cmac_64_with_lengths() throws Exception {
    CardProfile cardProfile = createProfileAes(SecurityBytesType.WITH_LENGHTS, false, SynchroCounterMode.NO_COUNTER);

    // The AES signature key
    final byte[] signatureKey = new byte[]{ (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16 };

    packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    byte[] data = new byte[]{ (byte) 0xab, (byte) 0x07, (byte) 0x80, (byte) 0x01, (byte) 0x01, (byte) 0x23, (byte) 0x02, (byte) 0x90, (byte) 0x00 };
    byte[] counter = new byte[]{ (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
    byte[] responsePacketBytes = packetBuilder.buildResponsePacket(data, counter, null, signatureKey, ResponsePacketStatus.POR_OK);

    Assert.assertArrayEquals(
        new byte[]{ (byte) 0x00, (byte) 0x1c, (byte) 0x12, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
            0x00,
            (byte) 0x4e, (byte) 0x5e, (byte) 0x7f, (byte) 0x13, (byte) 0x21, (byte) 0xdc, (byte) 0x96, (byte) 0x8b,
            (byte) 0xab, 0x07, (byte) 0x80, 0x01, 0x01, 0x23, 0x02, (byte) 0x90, 0x00 },
        responsePacketBytes);
  }

  @Test
  public void should_build_response_packet_cc_aes_cmac_64_with_lengths_and_udhl_ciphered() throws Exception {
    CardProfile cardProfile = createProfileAes(SecurityBytesType.WITH_LENGHTS_AND_UDHL, true, SynchroCounterMode.COUNTER_REPLAY_OR_CHECK);

    // The AES signature key
    final byte[] signatureKey = new byte[]{ (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16 };
    final byte[] cipheringKey = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    packetBuilder = PacketBuilderFactory.getInstance(cardProfile);

    byte[] data = new byte[]{ (byte) 0x90, (byte) 0x00 };
    byte[] counter = new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05 };
    byte[] responsePacketBytes = packetBuilder.buildResponsePacket(data, counter, cipheringKey, signatureKey, ResponsePacketStatus.POR_OK);

    ResponsePacket responsePacket = packetBuilder.recoverResponsePacket(responsePacketBytes, cipheringKey, signatureKey);

    Assert.assertEquals(ResponsePacketStatus.POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x00, 0x00, 0x01 }, responsePacket.getHeader().getTAR());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05 }, responsePacket.getHeader().getCounter());
    Assert.assertEquals(0x0f, responsePacket.getHeader().getPaddingCounter());
    Assert.assertEquals(POR_OK, responsePacket.getHeader().getResponseStatus());
    Assert.assertArrayEquals(new byte[]{ (byte) 0x90, (byte) 0x00},
        responsePacket.getData());
  }
}
