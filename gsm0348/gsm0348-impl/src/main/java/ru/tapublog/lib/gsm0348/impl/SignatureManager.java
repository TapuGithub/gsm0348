package ru.tapublog.lib.gsm0348.impl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.log4j.Logger;

/**
 * This utility class is used for signature operations during GSM 03.48 packet
 * creation and recovering. It performs redundancy check, digital signature and
 * cryptographic checksum algorithms.
 * 
 * @author Victor Platov
 */
public class SignatureManager
{
	private static final Logger LOGGER = Logger.getLogger(PacketBuilderImpl.class);

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

	public static byte[] sing(String algName, byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Signing. Data length:" + data.length);

		return doWork(algName, key, data);
	}

	public static boolean verify(String algName, byte[] key, byte[] data, byte[] signature) throws NoSuchAlgorithmException,
			InvalidKeyException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Verifying. Data length:" + data.length);

		return Arrays.equals(signature, doWork(algName, key, data));
	}

	private static byte[] doWork(String algName, byte[] key, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException
	{
		Mac mac = getMac(algName, key);
		byte[] result = mac.doFinal(data);
		return result;
	}

	public static int signLength(String algName) throws NoSuchAlgorithmException
	{
		Mac mac = Mac.getInstance(algName);
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Creating MAC for name:" + algName);
		final int macLength = mac.getMacLength();
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("MAC length:" + macLength);
		return macLength;
	}
}
