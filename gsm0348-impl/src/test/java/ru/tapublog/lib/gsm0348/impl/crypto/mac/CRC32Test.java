package ru.tapublog.lib.gsm0348.impl.crypto.mac;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class CRC32Test {

  // ETSI 102 225
  // If an input message is '01 02 03 04 05' where '01' is the first byte and '05' the last byte used for the
  // computation, then the result of CRC 32 computation applied to the input message is
  // '47 0B 99 F4', where '47' would represent the first byte and 'F4' the last byte of the RC/CC/DS field.

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