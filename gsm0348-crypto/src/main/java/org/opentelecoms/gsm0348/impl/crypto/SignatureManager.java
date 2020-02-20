package org.opentelecoms.gsm0348.impl.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.opentelecoms.gsm0348.api.Util;
import org.opentelecoms.gsm0348.impl.crypto.mac.CRC16X25;
import org.opentelecoms.gsm0348.impl.crypto.mac.CRC32;
import org.opentelecoms.gsm0348.impl.crypto.mac.DESMACISO9797M1;
import org.opentelecoms.gsm0348.impl.crypto.params.KeyParameter;
import org.opentelecoms.gsm0348.impl.crypto.params.ParametersWithIV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This utility class is used for signature operations during GSM 03.48 packet creation and recovering. It performs redundancy check, digital signature and
 * cryptographic checksum algorithms.
 *
 * @author Victor Platov
 */
public class SignatureManager {
  public static final String DES_MAC8_ISO9797_M1 = "DES_MAC8_ISO9797_M1";
  public static final String CRC_16 = "CRC16";
  public static final String CRC_32 = "CRC32";
  public static final String AES_CMAC_32 = "AES_CMAC_32";
  public static final String AES_CMAC_64 = "AES_CMAC_64";
  private static final Logger LOGGER = LoggerFactory.getLogger(SignatureManager.class);

  private SignatureManager() {
  }

  private static Mac getMac(String algName, byte[] key) throws InvalidKeyException, NoSuchAlgorithmException {
    LOGGER.debug("Creating MAC for name: {} with key length {}", algName, key.length);
    Mac mac = Mac.getInstance(algName);
    SecretKeySpec keySpec = new SecretKeySpec(key, algName);
    mac.init(keySpec);
    return mac;
  }

  private static byte[] runOwnMac(org.opentelecoms.gsm0348.impl.crypto.Mac mac, byte[] key, byte[] data, int size) {
    CipherParameters params = new ParametersWithIV(new KeyParameter(key), new byte[8]);
    mac.init(params);
    mac.update(data, 0, data.length);
    byte[] result = new byte[size];
    mac.doFinal(result, 0);
    return result;
  }

  public static byte[] sign(String algName, byte[] key, byte[] data)
      throws NoSuchAlgorithmException, InvalidKeyException {
    LOGGER.debug("Signing with algorithm {}. Data length: {}", algName, data.length);
    if (DES_MAC8_ISO9797_M1.equals(algName)) {
      return runOwnMac(new DESMACISO9797M1(), key, data, 8);
    }
    if (CRC_16.equals(algName)) {
      return runOwnMac(new CRC16X25(), key, data, 2);
    }
    if (CRC_32.equals(algName)) {
      return runOwnMac(new CRC32(), key, data, 4);
    }
    if (AES_CMAC_64.equals(algName)) {
      return truncate(doWork("AESCMAC", key, data), 8);
    }
    if (AES_CMAC_32.equals(algName)) {
      return truncate(doWork("AESCMAC", key, data), 4);
    }
    return doWork(algName, key, data);
  }

  private static byte[] truncate(final byte[] signature, final int length) {
    final byte[] value = new byte[length];
    System.arraycopy(signature, 0, value, 0, length);
    return value;
  }

  public static boolean verify(String algName, byte[] key, byte[] data, byte[] signature)
      throws NoSuchAlgorithmException, InvalidKeyException {
    LOGGER.debug("Verifying with algorithm {}. Data length: {}", algName, data.length);
    return Arrays.equals(signature, sign(algName, key, data));
  }

  private static byte[] doWork(final String algName, byte[] key, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException {
    final Mac mac = getMac(algName, key);
    final byte[] result = mac.doFinal(data);
    LOGGER.debug("MAC {} length: {} result: {}", algName, mac.getMacLength(), Util.toHexString(result));
    return result;
  }

  public static int signLength(final String algName) throws NoSuchAlgorithmException {
    LOGGER.debug("Creating MAC for algorithm: {}", algName);
    switch (algName) {
      case DES_MAC8_ISO9797_M1:
        return 8;
      case CRC_16:
        return 2;
      case CRC_32:
        return 4;
      case AES_CMAC_64:
        return 8;
      case AES_CMAC_32:
        return 4;
    }
    Mac mac = Mac.getInstance(algName);
    final int macLength = mac.getMacLength();
    return macLength;
  }
}
