package ru.tapublog.lib.gsm0348.api;
import ru.tapublog.lib.gsm0348.api.header.Counters;
import ru.tapublog.lib.gsm0348.api.header.TAR;
/**
 * This interface describes {@linkplain Packet GSM 03.48 packet} security
 * header.
 * 
 * @author Victor Platov
 */
public interface SecurityHeader extends PacketHeader
{
	/**
	 * Returns packet`s TAR.
	 * 
	 * @return {@linkplain TAR}
	 */
	TAR getTAR();
	/**
	 * Returns number of bytes used for padding.
	 * 
	 * @return paddingCounter.
	 */
	byte getPaddingCounter();
	/**
	 * Returns security bytes of packet. It can be RS/CC/DS or null in case
	 * security is not used. Length may vary but not less then 4 bytes.
	 * 
	 * @return security bytes.
	 */
	byte[] getSecurity();
	/**
	 * Returns counters bytes of packet. 
	 * 
	 * @return counters bytes.
	 */
	Counters getCounters();
}
