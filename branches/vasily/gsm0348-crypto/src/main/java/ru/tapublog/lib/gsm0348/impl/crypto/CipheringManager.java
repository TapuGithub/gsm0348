package ru.tapublog.lib.gsm0348.impl.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

/**
 * This utility class is used for ciphering operations during GSM 03.48 packet
 * creation and recovering.
 * 
 * @author Victor Platov
 */
public class CipheringManager
{
	private static final Logger LOGGER = Logger.getLogger(CipheringManager.class);

	private CipheringManager()
	{
	}

	private static final Cipher getCipher(final String alg) throws NoSuchAlgorithmException, NoSuchPaddingException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Creating cipher for name:" + alg);
		return Cipher.getInstance(alg);
	}

	/**
	 * Returns block size for transformation name specified. Name can be
	 * specified ether by only name, e.g.,DES or with mode and padding, e.g.,
	 * DES/EDE/ZerroBytePadding.
	 * 
	 * @param transformation
	 *            - the name of the transformation, e.g., DES/CBC/PKCS5Padding.
	 * @throws NullPointerException
	 *             if the transformation is null or empty string.
	 * @throws NoSuchAlgorithmException
	 *             if transformation with specified name not found
	 * @throws NoSuchPaddingException
	 *             if transformation contains a padding scheme that is not
	 *             available.
	 * @return cipher`s block size
	 */
	public static int getBlockSize(final String transformation) throws NoSuchAlgorithmException, NoSuchPaddingException
	{
		if (transformation == null || transformation.length() == 0)
			throw new IllegalArgumentException("Transformation name can not be null or empty");
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Getting blocksize for transformation: " + transformation);
		final int blockSize = getCipher(transformation).getBlockSize();
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Blocksize for transformation " + transformation + " is " + blockSize);
		return blockSize;
	}

	/**
	 * Deciphers data with specified transformation and key.
	 * 
	 * @param transformation
	 *            - the name of the transformation, e.g., DES/CBC/PKCS5Padding.
	 * @param key
	 *            - key for cipher.
	 * @param data
	 *            - data to be deciphered.
	 * 
	 * @throws NullPointerException
	 *             if transformation is null or empty, or key or data are null.
	 * @throws NoSuchAlgorithmException
	 *             if transformation with specified name not found.
	 * @throws NoSuchPaddingException
	 *             if transformation contains a padding scheme that is not
	 *             available.
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for this cipher, or if the
	 *             given key has a keysize that exceeds the maximum allowable
	 *             keysize.
	 * @throws IllegalBlockSizeException
	 *             if the length of data provided is incorrect, i.e., does not
	 *             match the block size of the cipher.
	 * @throws BadPaddingException
	 *             if particular padding mechanism is expected for the input
	 *             data but the data is not padded properly.
	 * @throws InvalidAlgorithmParameterException
	 *             if invalid or inappropriate algorithm parameters specified.
	 * @return deciphered data
	 */
	public static byte[] decipher(String transformation, byte[] key, byte[] data) throws IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Deciphering data");
        return doWork(transformation, key, data, new byte[]{0,0,0,0,0}, Cipher.DECRYPT_MODE);
	}

	private static void initCipher(Cipher cipher,int mode, byte[] key, byte[] iv) throws InvalidAlgorithmParameterException,
			InvalidAlgorithmParameterException, InvalidKeyException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Initializing cipher:" + cipher.getAlgorithm() + " key length: " + key.length * 8 + "bits");
		SecretKeySpec keySpec = new SecretKeySpec(key, cipher.getAlgorithm());
		if (cipher.getAlgorithm().contains("CBC"))
		{
			iv = new byte[8];
			IvParameterSpec spec = new IvParameterSpec(iv);
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Using IV:" + Arrays.toString(iv));
			cipher.init(mode, keySpec, spec);
		} else
			cipher.init(mode, keySpec);
	}

	/**
	 * Enciphers data with specified transformation, key and initialization
	 * vector.
	 * 
	 * @param transformation
	 *            - the name of the transformation, e.g., DES/CBC/PKCS5Padding.
	 * @param key
	 *            - key for cipher.
	 * @param iv
	 *            - initialization vector for cipher if used.
	 * @param data
	 *            - data to be enciphered.
	 * 
	 * @throws NullPointerException
	 *             if transformation is null or empty, or key, data or iv are
	 *             null.
	 * @throws NoSuchAlgorithmException
	 *             if transformation with specified name not found.
	 * @throws NoSuchPaddingException
	 *             if transformation contains a padding scheme that is not
	 *             available.
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for this cipher, or if the
	 *             given key has a keysize that exceeds the maximum allowable
	 *             keysize.
	 * @throws IllegalBlockSizeException
	 *             if the length of data provided is incorrect, i.e., does not
	 *             match the block size of the cipher.
	 * @throws BadPaddingException
	 *             if particular padding mechanism is expected for the input
	 *             data but the data is not padded properly.
	 * @throws InvalidAlgorithmParameterException
	 *             if invalid or inappropriate algorithm parameters specified.
	 * @return enciphered data
	 */
	public static byte[] encipher(String transformation, byte[] key, byte[] data, byte[] iv) throws IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Enciphering data");
		return doWork(transformation, key, data, iv, Cipher.ENCRYPT_MODE);
	}

	private static byte[] doWork(String transformation, byte[] key, byte[] data, byte[] iv, int mode)
			throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException
	{
		if (transformation == null || transformation.length() == 0 || key == null || data == null)
			throw new IllegalArgumentException();
		Cipher cipher = null;
		try
		{
			cipher = getCipher(transformation);
			initCipher(cipher, mode, key, iv);
			byte[] result = cipher.doFinal(data);
			return result;
		} catch (IllegalBlockSizeException e)
		{
			LOGGER.error(
					"Illegal block size. Input data size is " + data.length + " cipher block size is " + cipher.getBlockSize()
							+ " cipher name is " + cipher.getAlgorithm(), e);
			throw e;
		} catch (BadPaddingException e)
		{
			LOGGER.error(
					"Data isnot padded correctly. Input data size is " + data.length + " cipher block size is "
							+ cipher.getBlockSize() + " cipher name is " + cipher.getAlgorithm() + " data=["
							+ Util.toHexArray(data) + "]", e);
			throw e;
		} catch (InvalidAlgorithmParameterException e)
		{
			LOGGER.error("Invalid algorithm parameters. Transformation name:" + transformation, e);
			throw e;
		} catch (NoSuchAlgorithmException e)
		{
			LOGGER.error("Algorithm not found. Transformation name:" + transformation, e);
			throw e;
		} catch (NoSuchPaddingException e)
		{
			LOGGER.error("Padding scheme not found. Transformation name:" + transformation, e);
			throw e;
		} catch (InvalidKeyException e)
		{
			LOGGER.error("Invalid key provided. Key:" + Util.toHexArray(key), e);
			throw e;
		}
	}
}
