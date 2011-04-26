package ru.tapublog.lib.gsm0348.impl;

import java.io.File;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import junit.framework.TestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import ru.tapublog.lib.gsm0348.api.CommandPacket;
import ru.tapublog.lib.gsm0348.api.PacketBuilder;
import ru.tapublog.lib.gsm0348.api.PacketBuilderConfiguration;
import ru.tapublog.lib.gsm0348.impl.generated.Dataset;
import ru.tapublog.lib.gsm0348.impl.generated.TestCaseType;

public class DataDrivenPacketTest extends TestCase {
    private static final File CONFIG;
    
    static {
        final String cfg = System.getProperty("dataset_packet.path");
        CONFIG = new File(
                (cfg == null) ? "src/test/resources/Dataset0348.xml" : cfg);
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
			result[i] = Integer.valueOf(arr[i], 16).byteValue();
		}
    	return result;
    }
    
    private static PacketBuilderConfiguration getConvertedConfig(TestCaseType testcase) {
    	PacketBuilderConfigurationImpl convertedConfig = new PacketBuilderConfigurationImpl();
    	convertedConfig.setCipheringAlgorithm(testcase.getCipheringAlgorithm());
    	convertedConfig.setKIc(Integer.valueOf(testcase.getKIc().trim(), 16).byteValue());
    	convertedConfig.setKID(Integer.valueOf(testcase.getKID().trim(), 16).byteValue());
    	convertedConfig.setSignatureAlgorithm(testcase.getSignatureAlgorithm());
    	convertedConfig.setSPI(getByteArray(testcase.getSpi()));
    	convertedConfig.setTAR(getByteArray(testcase.getTar()));
    	return convertedConfig;
    }
    @Test
    public void testAll() throws Exception {
    	Dataset cfg = loadDataset();
    	
    	List<String> testNameList = new ArrayList<String>();
    	for (TestCaseType testcase : cfg.getTestcase()) {
    		final String name = testcase.getName();
    		if (testNameList.contains(name))
    			fail("Duplicated name found: " + name);
    		testNameList.add(name);
    	}
    	
    	boolean passed = true;
    	for (TestCaseType testcase : cfg.getTestcase()) {
			System.out.println("Running test id=" + testcase.getName());
    		PacketBuilder builder = PacketBuilderFactory.getInstance(getConvertedConfig(testcase));
    		CommandPacket packet = null;
    		try {
    			packet = builder.buildCommandPacket(getByteArray(testcase.getData()), getByteArray(testcase.getCounter()), getByteArray(testcase.getCipheringKey()), getByteArray(testcase.getSignatureKey()));
    		} catch (Exception exception) {
    			exception.printStackTrace();
    			passed = false;
    		}
    		
    		if (packet != null && !Arrays.equals(packet.toBytes(), getByteArray(testcase.getResult()))) {
    			System.out.println("Name: " + testcase.getName());
    			System.out.println(Util.toHexArray(packet.toBytes()));
    			System.out.println(Util.toHexArray(getByteArray(testcase.getResult())));
    			System.out.println("KIc: " + Util.toHexArray(getByteArray(testcase.getKIc())));
    			System.out.println("CipheringAlgorithm: " + testcase.getCipheringAlgorithm());
    			System.out.println("CipheringKey: " + Util.toHexArray(getByteArray(testcase.getCipheringKey())));
    			System.out.println("Counter: " + Util.toHexArray(getByteArray(testcase.getCounter())));
    			System.out.println("SPI: " + Util.toHexArray(getByteArray(testcase.getSpi())));
    			System.out.println("KID: " + Util.toHexArray(getByteArray(testcase.getKID())));
    			System.out.println("SignatureAlgorithm: " + testcase.getSignatureAlgorithm());
    			System.out.println("SignatureKey: " + Util.toHexArray(getByteArray(testcase.getSignatureKey())));
    			System.out.println("Data: " + Util.toHexArray(getByteArray(testcase.getData())));
    			System.out.println("Tar: " + Util.toHexArray(getByteArray(testcase.getTar())));
    			passed = false;
    		}
		}
		TestCase.assertTrue(passed);
    }
    
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

}
