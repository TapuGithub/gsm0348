package org.opentelecoms.gsm0348.api;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class UtilTest {

  @Test
  public void test_to_hex() {
    assertEquals("0xAB", Util.toHex((byte) 0xab));
  }

  @Test
  public void test_to_hex_string() {
    assertEquals("ABCD", Util.toHexString(new byte[]{ (byte) 0xab, (byte) 0xcd }));
    assertEquals("null", Util.toHexString(null));
  }

  @Test
  public void test_to_hex_array() {
    assertEquals("0xAB 0xCD", Util.toHexArray(new byte[]{ (byte) 0xab, (byte) 0xcd }));
  }

  @Test
  public void test_byte_to_int() {
    assertEquals(0, Util.byteToInt((byte) 0x00));
    assertEquals(1, Util.byteToInt((byte) 0x01));
    assertEquals(254, Util.byteToInt((byte) 0xfe));
    assertEquals(255, Util.byteToInt((byte) 0xff));
  }

}