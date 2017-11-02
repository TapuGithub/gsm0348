package ru.tapublog.lib.gsm0348.impl;

public class Util {
  private static final char kHexChars[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

  public static String toHex(final byte bt) {
    return Integer.toHexString(bt & (byte) 0xff).toUpperCase();
  }

  private static void appendHexPair(final byte b, final StringBuilder hexString) {
    hexString.append("0x");
    appendHexPairUnformatted(b, hexString);
  }

  public static String toHexArray(final byte[] array) {
    if (array == null) {
      return "null";
    }
    final StringBuilder sb = new StringBuilder();
    for (byte b : array) {
      appendHexPair(b, sb);
      sb.append(' ');
    }
    if (sb.length() > 0) {
      sb.deleteCharAt(sb.length() - 1);
    }
    return sb.toString();
  }

  public static String toHexString(final byte[] array) {
    if (array == null) {
      return "null";
    }
    final StringBuilder sb = new StringBuilder();
    for (byte b : array) {
      appendHexPairUnformatted(b, sb);
    }
    return sb.toString();
  }

  public static int unsignedByteToInt(byte b) {
    return b & 0xFF;
  }

  public static String toUnformattedHexArray(byte[] array) {
    StringBuilder sb = new StringBuilder();
    for (byte b : array) {
      appendHexPairUnformatted(b, sb);
    }
    return sb.toString();
  }

  private static void appendHexPairUnformatted(byte b, StringBuilder hexString) {
    char highNibble = kHexChars[(b & 0xF0) >> 4];
    char lowNibble = kHexChars[b & 0x0F];
    hexString.append(highNibble);
    hexString.append(lowNibble);
  }
}
