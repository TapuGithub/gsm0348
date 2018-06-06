package org.opentelecoms.gsm0348.impl.coders;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;
import org.opentelecoms.gsm0348.api.model.AlgorithmImplementation;
import org.opentelecoms.gsm0348.api.model.CipheringAlgorithmMode;
import org.opentelecoms.gsm0348.api.model.KIC;

public class KICCoderTest {

  @Test
  public void test_kic_00() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x00);
    assertEquals(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES, kic.getAlgorithmImplementation());
    assertNull(kic.getCipheringAlgorithmMode());
    assertEquals(0, kic.getKeysetID());
  }

  @Test
  public void test_kic_12() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x12);
    assertEquals(AlgorithmImplementation.AES, kic.getAlgorithmImplementation());
    assertEquals(CipheringAlgorithmMode.AES_CBC, kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
  }

  @Test
  public void test_kic_15() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x15);
    assertEquals(AlgorithmImplementation.DES, kic.getAlgorithmImplementation());
    assertEquals(CipheringAlgorithmMode.TRIPLE_DES_CBC_2_KEYS, kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
  }

  @Test
  public void test_kic_17() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x17);
    assertEquals(AlgorithmImplementation.PROPRIETARY_IMPLEMENTATIONS, kic.getAlgorithmImplementation());
    assertNull(kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
  }

  @Test
  public void test_kic_18() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x18);
    assertEquals(AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES, kic.getAlgorithmImplementation());
    assertNull(kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
  }

  @Test
  public void test_kic_19() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x19);
    assertEquals(AlgorithmImplementation.DES, kic.getAlgorithmImplementation());
    assertEquals(CipheringAlgorithmMode.TRIPLE_DES_CBC_3_KEYS, kic.getCipheringAlgorithmMode());
    assertEquals(1, kic.getKeysetID());
  }


  @Test
  public void test_kic_33() throws Exception {
    KIC kic = KICCoder.encode((byte) 0x33);
    assertEquals(AlgorithmImplementation.PROPRIETARY_IMPLEMENTATIONS, kic.getAlgorithmImplementation());
    assertNull(kic.getCipheringAlgorithmMode());
    assertEquals(3, kic.getKeysetID());
  }

  @Test
  public void test_kic_ff() throws Exception {
    KIC kic = KICCoder.encode((byte) 0xff);
    assertEquals(AlgorithmImplementation.PROPRIETARY_IMPLEMENTATIONS, kic.getAlgorithmImplementation());
    assertNull(kic.getCipheringAlgorithmMode());
    assertEquals(15, kic.getKeysetID());
  }
}