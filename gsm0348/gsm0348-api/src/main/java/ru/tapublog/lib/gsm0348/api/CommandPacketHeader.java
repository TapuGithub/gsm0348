package ru.tapublog.lib.gsm0348.api;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.KID;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.KIc;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.SPI;
/**
 * This interface describes {@linkplain CommandPacket GSM 03.48 Command packet} header.
 * 
 * @author Victor Platov
 */
public interface CommandPacketHeader extends SecurityHeader
{
	/**
	 * Returns {@linkplain SPI} of this header.
	 */
	SPI getSPI();
	/**
	 * Returns {@linkplain KIc} of this header.
	 */
	KIc getKIc();
	/**
	 * Returns {@linkplain KID} of this header.
	 */
	KID getKID();
}
