package ru.tapublog.lib.gsm0348.impl.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

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
public class SignatureManager
{
	private static final Logger LOGGER = Logger.getLogger(SignatureManager.class);
	public static final String DES_MAC8_ISO9797_M1 = "DES_MAC8_ISO9797_M1";
	
	private SignatureManager()
	{
	}

	private static Mac getMac(String algName, byte[] key) throws InvalidKeyException, NoSuchAlgorithmException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Creating MAC for name:" + algName + " with key length " + key.length);
		Mac mac = Mac.getInstance(algName);
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("MAC length:" + mac.getMacLength());
		SecretKeySpec keySpec = new SecretKeySpec(key, algName);
		mac.init(keySpec);
		return mac;
	}
	private static byte[] runOwnMac(ru.tapublog.lib.gsm0348.impl.crypto.Mac mac,byte[] key,byte[] data)
	{
		CipherParameters params = new ParametersWithIV(new KeyParameter(key), new byte[8]);
		mac.init(params);
		mac.update(data, 0, data.length);
		byte[] result = new byte[8];
		mac.doFinal(result, 0);
		return result;
	}
	public static byte[] sing(String algName, byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Signing. Data length:" + data.length);
		if(DES_MAC8_ISO9797_M1.equals(algName)) return runOwnMac(new DESMACISO9797M1(),key,data);
		
		return doWork(algName, key, data);
	}

	public static boolean verify(String algName, byte[] key, byte[] data, byte[] signature) throws NoSuchAlgorithmException,
			InvalidKeyException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Verifying. Data length:" + data.length);

		return Arrays.equals(signature, sing(algName, key, data));
	}

	private static byte[] doWork(String algName, byte[] key, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException
	{
		Mac mac = getMac(algName, key);
		byte[] result = mac.doFinal(data);
		return result;
	}

	public static int signLength(String algName) throws NoSuchAlgorithmException
	{
		if(DES_MAC8_ISO9797_M1.equals(algName)) // TODO: remove this block after adding something better
		{
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Creating MAC for name:" + algName);
			
			final int macLength = 8;
			
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("MAC length:" + macLength);
			return macLength;
		}
		Mac mac = Mac.getInstance(algName);
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Creating MAC for name:" + algName);
		
		final int macLength = mac.getMacLength();
		
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("MAC length:" + macLength);
		return macLength;
	}
}
