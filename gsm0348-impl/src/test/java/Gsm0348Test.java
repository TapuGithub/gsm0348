import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.impl.SimpleLogger;

import ru.tapublog.lib.gsm0348.api.PacketBuilder;
import ru.tapublog.lib.gsm0348.api.model.AlgorithmImplementation;
import ru.tapublog.lib.gsm0348.api.model.CardProfile;
import ru.tapublog.lib.gsm0348.api.model.CertificationAlgorithmMode;
import ru.tapublog.lib.gsm0348.api.model.CertificationMode;
import ru.tapublog.lib.gsm0348.api.model.CipheringAlgorithmMode;
import ru.tapublog.lib.gsm0348.api.model.CommandSPI;
import ru.tapublog.lib.gsm0348.api.model.KIC;
import ru.tapublog.lib.gsm0348.api.model.KID;
import ru.tapublog.lib.gsm0348.api.model.PoRMode;
import ru.tapublog.lib.gsm0348.api.model.PoRProtocol;
import ru.tapublog.lib.gsm0348.api.model.ResponsePacket;
import ru.tapublog.lib.gsm0348.api.model.ResponsePacketStatus;
import ru.tapublog.lib.gsm0348.api.model.ResponseSPI;
import ru.tapublog.lib.gsm0348.api.model.SPI;
import ru.tapublog.lib.gsm0348.api.model.SecurityBytesType;
import ru.tapublog.lib.gsm0348.api.model.SynchroCounterMode;
import ru.tapublog.lib.gsm0348.impl.PacketBuilderFactory;
import ru.tapublog.lib.gsm0348.impl.Util;

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
    Assert.assertArrayEquals(new byte[]{ 0x0A, (byte)0x90, 0x00 }, responsePacket.getData());
  }

  @Test
  public void should_build_response_packet() throws Exception {
    byte[] data = new byte[]{ (byte) 0x90, (byte) 0x00 };
    //byte[] counter = new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05 };
    byte[] responsePacketBytes = packetBuilder.buildResponsePacket(data, null, cipheringKey, signatureKey, ResponsePacketStatus.CIPHERING_ERROR);

    Assert.assertArrayEquals(new byte[]{ (byte) 0x00, 0x0D, 0x0A, (byte) 0xB0, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, (byte) 0x90, 0x00 }, responsePacketBytes);
  }
}
