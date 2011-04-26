package ru.tapublog.lib.gsm0348.impl;

import java.io.File;
import java.security.Security;
import java.util.Arrays;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import junit.framework.TestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import ru.tapublog.lib.gsm0348.api.PacketBuilder;
import ru.tapublog.lib.gsm0348.api.PacketBuilderConfiguration;
import ru.tapublog.lib.gsm0348.api.ResponsePacket;
import ru.tapublog.lib.gsm0348.impl.generated.portest.Dataset;
import ru.tapublog.lib.gsm0348.impl.generated.portest.Dataset.Testcase;

public class DataDrivenPoRTest {
    private static final File CONFIG;
    
    static {
        final String cfg = System.getProperty("dataset_por.path");
        CONFIG = new File(
                (cfg == null) ? "src/test/resources/Dataset0348_PoR.xml" : cfg);
        Security.addProvider(new BouncyCastleProvider());
    }

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}
	
    private static Dataset loadDataset() throws JAXBException {
        final JAXBContext ctx = JAXBContext.newInstance(Dataset.class);
        final Unmarshaller u = ctx.createUnmarshaller();
        return (Dataset) u.unmarshal(CONFIG);
    }

    private static byte[] getByteArray(String inStr) {
    	String[] arr = inStr.split(" +");
    	byte[] result = new byte[arr.length];
    	for (int i = 0; i < result.length; i++) {
			if (arr[i].length() != 0)
				result[i] = Integer.valueOf(arr[i], 16).byteValue();
		}
    	return result;
    }
    
    private static PacketBuilderConfiguration getConvertedConfig(Testcase testcase) {
    	PacketBuilderConfigurationImpl convertedConfig = new PacketBuilderConfigurationImpl();
    	convertedConfig.setCipheringAlgorithm(null);
    	convertedConfig.setKIc((byte)0);
    	convertedConfig.setKID(Integer.valueOf(testcase.getKID().trim(), 16).byteValue());
    	convertedConfig.setSignatureAlgorithm(null);
    	convertedConfig.setSPI(getByteArray(testcase.getSpi()));
    	convertedConfig.setTAR(getByteArray(testcase.getTar()));
    	return convertedConfig;
    }
    
    private static boolean comparePoR(ResponsePacket packet, byte[] tar, byte[] counters, byte[] data, byte respCode) {
    	if (! Arrays.equals(packet.getHeader().getTAR().toBytes(), tar)) return false;
    	if (! Arrays.equals(packet.getHeader().getCounters().toBytes(), counters)) return false;
    	if (! Arrays.equals(packet.getData().toBytes(), data)) return false;
    	if (packet.getHeader().getResponseStatus().getCode() != respCode) return false;
    	return true;
    }
    
    @Test
    public void testAll() throws Exception {
    	Dataset cfg = loadDataset();
    	int i = 0;
    	for (Testcase testcase : cfg.getTestcase()) {
    		++i;
			System.out.println("Running test id=" + i);
    		PacketBuilder builder = PacketBuilderFactory.getInstance(getConvertedConfig(testcase));
    		ResponsePacket packet = builder.recoverResponsePacket(getByteArray(testcase.getResponse()), getByteArray(testcase.getCipheringKey()), getByteArray(testcase.getSignatureKey()));
    		if (!comparePoR(packet, getByteArray(testcase.getTar()), getByteArray(testcase.getCounter()), getByteArray(testcase.getResultData()), Byte.parseByte(testcase.getResultCode(), 16))) {
    			System.out.println(Util.toHexArray(packet.toBytes()));
    			System.out.println("Response: " + Util.toHexArray(getByteArray(testcase.getResponse())));
    			System.out.println("CipheringKey: " + Util.toHexArray(getByteArray(testcase.getCipheringKey())));
    			System.out.println("SignatureKey: " + Util.toHexArray(getByteArray(testcase.getSignatureKey())));
    			System.out.println("Counter: " + Util.toHexArray(getByteArray(testcase.getCounter())));
    			System.out.println("SPI: " + Util.toHexArray(getByteArray(testcase.getSpi())));
    			System.out.println("KID: " + Util.toHexArray(getByteArray(testcase.getKID())));
    			System.out.println("Tar: " + Util.toHexArray(getByteArray(testcase.getTar())));
    			System.out.println("PoR Data: " + Util.toHexArray(getByteArray(testcase.getResultData())));
    			System.out.println("PoR Code: " + Util.toHexArray(getByteArray(testcase.getResultCode())));
    			TestCase.fail();
    		}
		}
    }
    
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

}
