package ru.tapublog.lib.gsm0348.impl.crypto;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ru.tapublog.lib.gsm0348.impl.crypto.mac.DESMACISO9797M1;
import ru.tapublog.lib.gsm0348.impl.crypto.params.KeyParameter;
import ru.tapublog.lib.gsm0348.impl.crypto.params.ParametersWithIV;

/**
 * This utility class is used for signature operations during GSM 03.48 packet
 * creation and recovering. It performs redundancy check, digital signature and
 * cryptographic checksum algorithms.
 *
 * @author Victor Platov
 */
public class SignatureManager {
  private static final Logger LOGGER = LoggerFactory.getLogger(SignatureManager.class);
  public static final String DES_MAC8_ISO9797_M1 = "DES_MAC8_ISO9797_M1";
  public static final String CRC_32 = "CRC-32";

  private SignatureManager() {
  }

  private static Mac getMac(String algName, byte[] key) throws InvalidKeyException, NoSuchAlgorithmException {
    LOGGER.debug("Creating MAC for name: {} with key length {}", algName, key.length);
    Mac mac = Mac.getInstance(algName);
    LOGGER.debug("MAC length: {}", mac.getMacLength());
    SecretKeySpec keySpec = new SecretKeySpec(key, algName);
    mac.init(keySpec);
    return mac;
  }

  private static byte[] runOwnMac(ru.tapublog.lib.gsm0348.impl.crypto.Mac mac, byte[] key, byte[] data) {
    CipherParameters params = new ParametersWithIV(new KeyParameter(key), new byte[8]);
    mac.init(params);
    mac.update(data, 0, data.length);
    byte[] result = new byte[8];
    mac.doFinal(result, 0);
    return result;
  }

  public static byte[] sign(String algName, byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
    LOGGER.debug("Signing. Data length: {}", data.length);
    if (DES_MAC8_ISO9797_M1.equals(algName)) {
      return runOwnMac(new DESMACISO9797M1(), key, data);
    }
    if (CRC_32.equals(algName)) {
      Checksum checksum = new CRC32();
      checksum.update(data, 0, data.length);
      ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE / Byte.SIZE);
      buffer.putLong(checksum.getValue());
      byte[] rc = buffer.array();
      return Arrays.copyOfRange(rc, 4, rc.length);
    }
    return doWork(algName, key, data);
  }

  public static boolean verify(String algName, byte[] key, byte[] data, byte[] signature) throws NoSuchAlgorithmException,
      InvalidKeyException {
    LOGGER.debug("Verifying. Data length: {}", data.length);

    return Arrays.equals(signature, sign(algName, key, data));
  }

  private static byte[] doWork(final String algName, byte[] key, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException {
    final Mac mac = getMac(algName, key);
    final byte[] result = mac.doFinal(data);
    return result;
  }

  public static int signLength(final String algName) throws NoSuchAlgorithmException {
    LOGGER.info("Creating MAC for name: {}", algName);
    if (DES_MAC8_ISO9797_M1.equals(algName)) // TODO: remove this block after adding something better
    {
      final int macLength = 8;
      LOGGER.info("MAC length: {}", macLength);
      return macLength;
    }
    else if (CRC_32.equals(algName)) {
      final int macLength = 4;
      LOGGER.info("MAC length: {}", macLength);
      return macLength;
    }
    Mac mac = Mac.getInstance(algName);
    final int macLength = mac.getMacLength();

    LOGGER.info("MAC length: {}", macLength);
    return macLength;
  }
}
