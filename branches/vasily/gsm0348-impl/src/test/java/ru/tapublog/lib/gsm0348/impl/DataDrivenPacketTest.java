package ru.tapublog.lib.gsm0348.impl;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.ParserConfigurationException;

import junit.framework.TestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.SAXException;

import ru.tapublog.lib.gsm0348.api.PacketBuilder;
import ru.tapublog.lib.gsm0348.api.model.ResponsePacket;
import ru.tapublog.lib.gsm0348.impl.generated.Dataset;
import ru.tapublog.lib.gsm0348.impl.generated.TestCaseType;

public class DataDrivenPacketTest extends TestCase
{
	private static final File CONFIG;

	static
	{
		final String cfg = System.getProperty("dataset_packet.path");
		CONFIG = new File((cfg == null) ? "src/test/resources/Dataset0348.xml" : cfg);
		Security.addProvider(new BouncyCastleProvider());
	}

	@BeforeClass
	public static void setUpBeforeClass() throws Exception
	{

	}

	private static Dataset loadDataset() throws JAXBException,IOException,SAXException,ParserConfigurationException
	{
		final JAXBContext ctx = JAXBContext.newInstance("ru.tapublog.lib.gsm0348.api.model:ru.tapublog.lib.gsm0348.impl.generated");
		final Unmarshaller u = ctx.createUnmarshaller();
	
		return (Dataset) u.unmarshal(CONFIG);
	}

	@Test
	public void testAll() throws Exception
	{
		Dataset cfg = loadDataset();

		List<String> testNameList = new ArrayList<String>();
		for (TestCaseType testcase : cfg.getTestcase())
		{
			final String name = testcase.getName();
			if (testNameList.contains(name))
				fail("Duplicated name found: " + name);
			testNameList.add(name);
		}

		boolean passed = true;
		for (TestCaseType testcase : cfg.getTestcase())
		{
			System.out.println("Running test id=" + testcase.getName());
			PacketBuilder builder = new PacketBuilderImpl(testcase.getCardProfile().getValue());//PacketBuilderFactory.getInstance(testcase.getCardProfile());
			if(testcase.getType().equals("request"))
			{
				byte[] packet = null;
				try
				{
					packet = builder.buildCommandPacket(testcase.getData(), testcase.getCounter(), testcase.getCipheringKey(),
							testcase.getSignatureKey());
				}
				catch (Exception exception)
				{
					exception.printStackTrace();
					passed = false;
				}

				if (packet != null && !Arrays.equals(packet, testcase.getResult().getRequestResult()))
				{
					System.out.println("Name: " + testcase.getName());
					System.out.println("Found: \t" + Util.toHexArray(packet));
					System.out.println("Expected: \t" + Util.toHexArray(testcase.getResult().getRequestResult()));
					passed = false;
				}
			}
			else
			{
				ResponsePacket packet = null;
				try
				{
					packet = builder.recoverResponsePacket(testcase.getData(), testcase.getCipheringKey(), testcase.getSignatureKey());
				}
				catch (Exception exception)
				{
					exception.printStackTrace();
					passed = false;
				}
				
				if (packet == null ||  !compareResponsePackets(testcase.getResult().getResponseResult().getValue(),packet))
				{
					System.out.println("Name: " + testcase.getName());
					System.out.println("Found: " + packet);
					System.out.println("Expected: " + testcase.getResult().getResponseResult().getValue());
					passed = false;
				}
			}
		
		}
		TestCase.assertTrue(passed);
	}

	private boolean compareResponsePackets(ResponsePacket rp1, ResponsePacket rp2)
	{
		return rp1.equals(rp2);
	}
	@AfterClass
	public static void tearDownAfterClass() throws Exception
	{
	}

}
