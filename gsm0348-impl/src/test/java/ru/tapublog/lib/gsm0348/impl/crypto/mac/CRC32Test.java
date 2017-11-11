package ru.tapublog.lib.gsm0348.impl.crypto.mac;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class CRC32Test {

  // 0x01 0x02 0x03 0x04 0x05
  @Test
  public void test_crc32() throws Exception {
    CRC32 crc32 = new CRC32();
    crc32.init(null);
    final byte[] data = new byte[]{ (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05 };
    crc32.update(data, 0, data.length);
    final byte[] crc = new byte[4];
    final int bytesCopied = crc32.doFinal(crc, 0);
    assertEquals(4, bytesCopied);
    assertArrayEquals(new byte[]{ (byte) 0x47, (byte) 0x0B, (byte) 0x99, (byte) 0xF4 }, crc);
  }
}