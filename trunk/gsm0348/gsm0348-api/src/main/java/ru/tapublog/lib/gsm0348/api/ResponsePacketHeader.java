package ru.tapublog.lib.gsm0348.api;
import ru.tapublog.lib.gsm0348.api.header.responsepacket.GSM0348ResponsePacketStatusCode;
/**
 * This interface describes {@linkplain ResponsePacket GSM 03.48 Response packet} header.
 * 
 * @author Victor Platov
 */
public interface ResponsePacketHeader extends SecurityHeader
{
	/**
	 * Returns packet`s status code.
	 * 
	 * @return {@linkplain GSM0348ResponsePacketStatusCode status code.}
	 */
	GSM0348ResponsePacketStatusCode getResponseStatus();
}
