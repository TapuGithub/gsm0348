package ru.tapublog.lib.gsm0348.api;
import ru.tapublog.lib.gsm0348.api.header.responsepacket.GSM0348ResponsePacketStatusCode;
/**
 * This interface describes GSM 03.48 packet builder. Instances of this
 * interface must create and recover GSM 03.48 {@linkplain CommandPacket} and
 * {@linkplain ResponsePacket} including their enciphering,deciphering,
 * signing(RC,CC,DS) and signature verification.
 * 
 * @author Victor Platov
 */
public interface PacketBuilder
{
	/**
	 * Sets builder configuration providing all needed for packet builder and
	 * recovering information. Builder <strong>must</strong> be configured
	 * before usage. Configuration state can be checked using
	 * {@linkplain PacketBuilder#isConfigured isConfigured} method.
	 * 
	 * @param builderConfiguration
	 *            - any {@linkplain PacketBuilderConfiguration} instance.
	 * @throws NullPointerException
	 *             if <strong>builderConfiguration</strong> parameter is null.
	 * @throws PacketBuilderConfigurationException
	 *             if configuration is in inconsistent state.
	 */
	void setConfiguration(PacketBuilderConfiguration builderConfiguration) throws PacketBuilderConfigurationException;
	/**
	 * Returns configuration used or null if builder is not configured.
	 * 
	 * @return {@linkplain PacketBuilderConfiguration} used.
	 */
	PacketBuilderConfiguration getConfiguration();
	/**
	 * Returns builder configuration state. After
	 * {@linkplain PacketBuilder#setConfiguration setConfiguration} method
	 * called if no exception thrown builder should turn no configured state and
	 * this method return <code>true</code>. Otherwise it will should return
	 * <code>false</code>.
	 * 
	 * @return builder configuration state
	 */
	boolean isConfigured();
	/**
	 * Builds {@linkplain CommandPacket}.
	 * 
	 * @param data
	 *            - data to be sent. Can be null if no data sending needed.
	 * @param counters
	 *            - counters value. If not used can be null.
	 * @param cipheringKey
	 *            - ciphering key. Used only if enciphering is needed, otherwise
	 *            can be null.
	 * @param signatureKey
	 *            - signature key. Used only if signing is needed, otherwise can
	 *            be null.
	 * @return {@linkplain CommandPacket}
	 * @throws PacketBuilderConfigurationException
	 *             if builder if not configured or if ciphering and/or signing
	 *             is on but key is not provided.
	 * @throws SimUpdaterException
	 *             in other cases.
	 * 
	 */
	CommandPacket buildCommandPacket(byte[] data, byte[] counters, byte[] cipheringKey, byte[] signatureKey)
			throws PacketBuilderConfigurationException, Gsm0348Exception;
	/**
	 * Recovers {@linkplain ResponsePacket} from byte array.
	 * 
	 * @param data
	 *            - data to be decoded.
	 * @param cipheringKey
	 *            - ciphering key. Used only if enciphering is needed, otherwise
	 *            can be null.
	 * @param signatureKey
	 *            - signature key. Used only if signing is needed, otherwise can
	 *            be null.
	 * @return {@linkplain ResponsePacket}
	 * @throws NullPointerException
	 *             if data is null or empty.
	 * @throws PacketBuilderConfigurationException
	 *             if builder if not configured or if ciphering and/or signing
	 *             is on but key is not provided.
	 * @throws SimUpdaterException
	 *             in other cases.
	 * 
	 */
	ResponsePacket recoverResponsePacket(byte[] data, byte[] cipheringKey, byte[] signatureKey)
			throws PacketBuilderConfigurationException, Gsm0348Exception;
	/**
	 * Builds {@linkplain ResponsePacket}. Not implemented.
	 * 
	 * @param data
	 *            - data to be sent. Can be null if no data sending needed.
	 * @param counters
	 *            - counters value. If not used can be null.
	 * @param cipheringKey
	 *            - ciphering key. Used only if enciphering is needed, otherwise
	 *            can be null.
	 * @param signatureKey
	 *            - signature key. Used only if signing is needed, otherwise can
	 *            be null.
	 * @param responseCode
	 *            - {@linkplain GSM0348ResponsePacketStatusCode} of the building
	 *            message.
	 * @return {@linkplain ResponsePacket}
	 * @throws PacketBuilderConfigurationException
	 *             if builder if not configured or if ciphering and/or signing
	 *             is on but key is not provided.
	 * @throws SimUpdaterException
	 *             in other cases.
	 * 
	 */
	@Deprecated
	ResponsePacket buildResponsePacket(byte[] data, byte[] counters, byte[] cipheringKey, byte[] signatureKey,
			GSM0348ResponsePacketStatusCode responseCode) throws PacketBuilderConfigurationException, Gsm0348Exception;
	/**
	 * Recovers {@linkplain CommandPacket} from byte array. Not implemented.
	 * 
	 * @param data
	 *            - data to be decoded.
	 * @param cipheringKey
	 *            - ciphering key. Used only if enciphering is needed, otherwise
	 *            can be null.
	 * @param signatureKey
	 *            - signature key. Used only if signing is needed, otherwise can
	 *            be null.
	 * @return {@linkplain CommandPacket}
	 * @throws NullPointerException
	 *             if data is null or empty.
	 * @throws PacketBuilderConfigurationException
	 *             if builder if not configured or if ciphering and/or signing
	 *             is on but key is not provided.
	 * @throws SimUpdaterException
	 *             in other cases.
	 * 
	 */
	@Deprecated
	CommandPacket recoverCommandPacket(byte[] data, byte[] cipheringKey, byte[] signatureKey)
			throws PacketBuilderConfigurationException, Gsm0348Exception;
}
