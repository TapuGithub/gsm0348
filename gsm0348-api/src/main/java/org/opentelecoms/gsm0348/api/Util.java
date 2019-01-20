package org.opentelecoms.gsm0348.api;

public class Util {

  private static final char HEX_CHARS[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

  public static String toHex(final byte b) {
    return new String(new char[]{ '0', 'x', HEX_CHARS[(b & 0xf0) >> 4], HEX_CHARS[b & 0x0f] });
  }

  private static void appendHex(byte b, StringBuilder hexString) {
    final char highNibble = HEX_CHARS[(b & 0xf0) >> 4];
    final char lowNibble = HEX_CHARS[b & 0x0f];
    hexString.append(highNibble);
    hexString.append(lowNibble);
  }

  private static void appendHexPair(final byte b, final StringBuilder hexString) {
    hexString.append("0x");
    appendHex(b, hexString);
  }

  public static String toHexString(final byte[] array) {
    if (array == null) {
      return "null";
    }
    final StringBuilder sb = new StringBuilder();
    for (byte b : array) {
      appendHex(b, sb);
    }
    return sb.toString();
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

  public static int byteToInt(final byte b) {
    return b & 0xff;
  }
}
