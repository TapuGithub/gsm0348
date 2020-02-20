package org.opentelecoms.gsm0348.impl.crypto;

public interface Mac
{
	void init(CipherParameters paramCipherParameters) throws IllegalArgumentException;

	String getAlgorithmName();

	int getMacSize();

	void update(byte paramByte) throws IllegalStateException;

	void update(byte[] paramArrayOfByte, int paramInt1, int paramInt2) throws IllegalStateException;

	int doFinal(byte[] paramArrayOfByte, int paramInt) throws IllegalStateException;

	void reset();
}
