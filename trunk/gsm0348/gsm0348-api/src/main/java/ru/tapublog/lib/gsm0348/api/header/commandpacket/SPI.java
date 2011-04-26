package ru.tapublog.lib.gsm0348.api.header.commandpacket;

/**
 * This interface describes GSM 03.48 Security Parameters Indication. It
 * consists of two parts - {@linkplain CommandSPI} and {@linkplain ResponseSPI}.
 * 
 * @author Victor Platov
 */
public interface SPI
{
	/**
	 * Returns {@linkplain CommandSPI}.
	 * 
	 * @return {@linkplain CommandSPI}
	 */
	CommandSPI getCommandSPI();

	/**
	 * Returns {@linkplain ResponseSPI}.
	 * 
	 * @return {@linkplain ResponseSPI}
	 */
	ResponseSPI getResponseSPI();
}
