package ru.tapublog.lib.gsm0348.impl.crypto.mac;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class CRC16X25Test {

  @Test
  public void test_crc16_x25() throws Exception {
    CRC16X25 crc16X25 = new CRC16X25();
    crc16X25.init(null);
    final byte[] data = new byte[]{ (byte) 0xFF, (byte) 0x10, (byte) 0x9A, (byte) 0x45, (byte) 0xF2, 0x7B, (byte) 0xF1, (byte) 0x00 };
    crc16X25.update(data, 0, data.length);
    final byte[] crc = new byte[2];
    final int bytesCopied = crc16X25.doFinal(crc, 0);
    assertEquals(2, bytesCopied);
    assertArrayEquals(new byte[]{ (byte) 0xCF, (byte) 0x0A }, crc);
  }
}