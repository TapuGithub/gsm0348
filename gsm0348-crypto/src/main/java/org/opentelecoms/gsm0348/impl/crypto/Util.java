package org.opentelecoms.gsm0348.impl.crypto;

public class Util
{
	private static final char kHexChars[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	private static void appendHex(byte b, StringBuilder hexString)
	{
		char highNibble = kHexChars[(b & 0xF0) >> 4];
		char lowNibble = kHexChars[b & 0x0F];
		hexString.append(highNibble);
		hexString.append(lowNibble);
	}

	private static void appendHexPair(byte b, StringBuilder hexString)
	{
		hexString.append("0x");
		appendHex(b, hexString);
	}

	public static String toHexString(byte[] array)
	{
		if (array == null) {
			return "null";
		}
		StringBuilder sb = new StringBuilder();
		for (byte b : array)
		{
			appendHex(b, sb);
		}
		return sb.toString();
	}
 
	public static String toHexArray(byte[] array)
	{
		if (array == null) {
			return "null";
		}
		StringBuilder sb = new StringBuilder();
		for (byte b : array)
		{
			appendHexPair(b, sb);
			sb.append(' ');
		}
		if (sb.length() > 0) {
			sb.deleteCharAt(sb.length() - 1);
		}
		return sb.toString();
	}
}
