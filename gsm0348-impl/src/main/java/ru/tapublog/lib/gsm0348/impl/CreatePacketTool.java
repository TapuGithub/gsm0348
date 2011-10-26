//package ru.tapublog.lib.gsm0348.impl;
//
//import org.apache.commons.cli.CommandLine;
//import org.apache.commons.cli.CommandLineParser;
//import org.apache.commons.cli.HelpFormatter;
//import org.apache.commons.cli.Option;
//import org.apache.commons.cli.Options;
//import org.apache.commons.cli.ParseException;
//import org.apache.commons.cli.PosixParser;
//
//import ru.tapublog.lib.gsm0348.api.Gsm0348Exception;
//import ru.tapublog.lib.gsm0348.api.PacketBuilder;
//import ru.tapublog.lib.gsm0348.api.old.api.CommandPacket;
//import ru.tapublog.lib.gsm0348.api.old.api.PacketBuilderConfiguration;
//import ru.tapublog.lib.gsm0348.impl.old.PacketBuilderConfigurationImpl;
//
///**
// * CLI tool for packet generation. Provides command line interface to
// * {@linkplain PacketBuilder}.
// * 
// * @author Victor Platov
// */
//public class CreatePacketTool
//{
//	public static void main(String[] args) throws ParseException
//	{
//
//		Options options = new Options();
//		options.addOption("kid", true, "Packet KID byte value in HEX. Default is 00. MUST be 1 byte long.");
//
//		options.addOption("kic", true, "Packet KIc byte value in HEX. Default is 00. MUST be 1 byte long.");
//
//		options.addOption("tar", true, "Packet TAR three byte value in HEX. Default is 00 00 00. MUST be 3 bytes long.");
//		options.getOption("tar").setArgs(Option.UNLIMITED_VALUES);
//
//		options.addOption("spi", true, "Packet SPI two byte value in HEX. Default is 00 00. MUST be 2 bytes long.");
//		options.getOption("spi").setArgs(Option.UNLIMITED_VALUES);
//
//		options.addOption(
//				"ca",
//				"cipheringAlgorithm",
//				true,
//				"Packet ciphering alorithm value if used. Default is DES/CBC/ZeroBytePadding.Algorithm list can be found here - http://www.bouncycastle.org/specifications.html.");
//
//		options.addOption("ck", "cipheringKey", true,
//				"Packet ciphering alorithm`s key value if used. Default is 00 00 00 00 00 00 00 00. Length depends on algorithm.");
//		options.getOption("ck").setArgs(Option.UNLIMITED_VALUES);
//
//		options.addOption(
//				"sa",
//				"signatureAlgorithm",
//				true,
//				"Packet signature alorithm value if used. Default is DESMac. Algorithm list can be found here - http://www.bouncycastle.org/specifications.html.");
//
//		options.addOption("sk", "signatureKey", true,
//				"Packet signature alorithm`s key value if used. Default is 00 00 00 00 00 00 00 00. Length depends on algorithm.");
//		options.getOption("sk").setArgs(Option.UNLIMITED_VALUES);
//
//		options.addOption("co", "counter", true, "Packet counter value.  Default is 00 00 00 00 00. MUST be 5 bytes long.");
//		options.getOption("co").setArgs(Option.UNLIMITED_VALUES);
//
//		options.addOption("d", "data", true, "Packet data. Default is no data.");
//		options.getOption("d").setArgs(Option.UNLIMITED_VALUES);
//
//		options.addOption("v", "verbose", false, "Print packet meaning after raw data.");
//		options.addOption("u", "usage", false, "Print usage.");
//
//		CommandLineParser parser = new PosixParser();
//
//		CommandLine line = parser.parse(options, args);
//
//		if (line.hasOption('u'))
//		{
//			HelpFormatter helpF = new HelpFormatter();
//			helpF.printHelp("java com.hp.opencall.services.dsp.simupdater.gsm0348.impl.CreatePacketTool", options);
//			return;
//		}
//		PacketBuilderConfiguration params = new PacketBuilderConfigurationImpl();
//
//		params.setKIc(Byte.parseByte(line.getOptionValue("kic", "00"), 16));
//		params.setKID(Byte.parseByte(line.getOptionValue("kid", "00"), 16));
//
//		if (line.hasOption("tar"))
//			params.setTAR(getByteArray(line.getOptionValues("tar")));
//		else
//			params.setTAR(new byte[3]);
//
//		if (line.hasOption("spi"))
//			params.setSPI(getByteArray(line.getOptionValues("spi")));
//		else
//			params.setSPI(new byte[2]);
//
//		params.setCipheringAlgorithm(line.getOptionValue("ca", "DES/CBC/ZeroBytePadding"));
//
//		byte[] ck;
//		if (line.hasOption("ck"))
//			ck = getByteArray(line.getOptionValues("ck"));
//		else
//			ck = new byte[8];
//
//		params.setSignatureAlgorithm(line.getOptionValue("sa", "DESMac"));
//
//		byte[] sk;
//		if (line.hasOption("sk"))
//			sk = getByteArray(line.getOptionValues("sk"));
//		else
//			sk = new byte[8];
//
//		byte[] data;
//		if (line.hasOption("d"))
//			data = getByteArray(line.getOptionValues("d"));
//		else
//			data = new byte[0];
//
//		byte[] counter;
//		if (line.hasOption("co"))
//			counter = getByteArray(line.getOptionValues("co"));
//		else
//			counter = new byte[5];
//
//		try
//		{
//			PacketBuilder builder = PacketBuilderFactory.getInstance(params);
//			CommandPacket packet = builder.buildCommandPacket(data, counter, ck, sk);
//			System.out.println(Util.toUnformattedHexArray(packet.toBytes()));
//			if (line.hasOption('v'))
//				System.out.println(packet);
//		} catch (Gsm0348Exception ex)
//		{
//			ex.printStackTrace();
//		}
//
//	}
//
//	private static byte[] getByteArray(String[] in)
//	{
//		byte[] result = new byte[in.length];
//		for (int i = 0; i < in.length; i++)
//		{
//			result[i] = (byte) Integer.parseInt(in[i], 16);
//		}
//
//		return result;
//	}
//}
