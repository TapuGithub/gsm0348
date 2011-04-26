package ru.tapublog.lib.gsm0348.api;

/**
 * This interface describes {@linkplain PacketBuilder} configuration. It is used
 * to configure {@linkplain PacketBuilder} instances.
 * 
 * @author Victor Platov
 */
public interface PacketBuilderConfiguration
{
	/**
	 * Returns KIc byte.
	 * 
	 * @return KIc byte.
	 */
	byte getKIc();

	/**
	 * Sets KIc (Key and algorithm Identifier for ciphering) byte. The KIc is
	 * coded as below. <br>
	 * <table>
	 * <col width="25%"/> <col width="75%"/> <thead>
	 * <tr>
	 * <th>Bytes</th>
	 * <th>Values</th>
	 * </tr>
	 * <thead> <tbody>
	 * <tr>
	 * <td>b2b1</td>
	 * <td>00: Algorithm known implicitly by both entities<br>
	 * 01: DES<br>
	 * 10: Reserved<br>
	 * 11: Proprietary Implementations</td>
	 * </tr>
	 * <tr>
	 * <td>b4b3</td>
	 * <td>00: DES in CBC mode<br>
	 * 01: Triple DES in outer-CBC mode using two different keys<br>
	 * 10: Triple DES in outer-CBC mode using three different keys<br>
	 * 11: DES in ECB mode</td>
	 * </tr>
	 * <tr>
	 * <td>b8b7b6b5</td>
	 * <td>indication of Keys to be used (keys implicitly agreed between both
	 * entities)</td>
	 * </tr>
	 * </tbody>
	 * </table>
	 * 
	 * @param kic
	 *            value.
	 */
	void setKIc(byte kic);

	/**
	 * Returns KID byte.
	 * 
	 * @return KID byte.
	 */
	byte getKID();

	/**
	 * Sets KID (Key and algorithm Identifier for RC/CC/DS) byte. The KID is
	 * coded as below. <br>
	 * <table>
	 * <col width="25%"/> <col width="75%"/> <thead>
	 * <tr>
	 * <th>Bytes</th>
	 * <th>Values</th>
	 * </tr>
	 * <thead> <tbody>
	 * <tr>
	 * <td>b2b1</td>
	 * <td>00: Algorithm known implicitly by both entities<br>
	 * 01: DES<br>
	 * 10: Reserved<br>
	 * 11: Proprietary Implementations</td>
	 * </tr>
	 * <tr>
	 * <td>b4b3</td>
	 * <td>00: DES in CBC mode<br>
	 * 01: Triple DES in outer-CBC mode using two different keys<br>
	 * 10: Triple DES in outer-CBC mode using three different keys<br>
	 * 11: Reserved</td>
	 * </tr>
	 * <tr>
	 * <td>b8b7b6b5</td>
	 * <td>indication of Keys to be used (keys implicitly agreed between both
	 * entities)</td>
	 * </tr>
	 * </tbody>
	 * </table>
	 * 
	 * @param kid
	 *            value.
	 */
	void setKID(byte kid);

	/**
	 * Returns TAR bytes.
	 * 
	 * @return byte[3]
	 */
	byte[] getTAR();

	/**
	 * Sets TAR (Toolkit Application Reference).
	 * 
	 * @param tar
	 *            - byte[3].
	 * @throws IllegalArgumentException
	 *             if <strong>tar</strong> length is not 3.
	 */
	void setTAR(byte[] tar) throws IllegalArgumentException;

	/**
	 * Returns SPI bytes.
	 * 
	 * @return byte[2]
	 */
	byte[] getSPI();

	/**
	 * Sets SPI (Security Parameters Indication).
	 * <p>
	 * Byte 1.
	 * <table>
	 * <col width="25%"/> <col width="75%"/> <thead>
	 * <tr>
	 * <th>Bytes</th>
	 * <th>Values</th>
	 * </tr>
	 * <thead> <tbody>
	 * <tr>
	 * <td>b2b1</td>
	 * <td>00: No RC, CC or DS<br>
	 * 01: Redundancy Check<br>
	 * 10: Cryptographic Checksum<br>
	 * 11: Digital Signature</td>
	 * </tr>
	 * <tr>
	 * <td>b3</td>
	 * <td>0 : No Ciphering<br>
	 * 1 : Ciphering<br>
	 * </tr>
	 * <tr>
	 * <td>b5b4</td>
	 * <td>00: No counter available<br>
	 * 01: Counter available; no replay or sequence checking<br>
	 * 10: Process if and only if counter value is higher than the value in the
	 * RE<br>
	 * 11: Process if and only if counter value is one higher than the value in
	 * the RE</td>
	 * </tr>
	 * <tr>
	 * <td>b8b7b6</td>
	 * <td>Reserved (set to zero and ignored by RE)<br>
	 * </tr>
	 * </tbody>
	 * </table>
	 * 
	 * <p>
	 * Byte 2.
	 * <table>
	 * <col width="25%"/> <col width="75%"/> <thead>
	 * <tr>
	 * <th>Bytes</th>
	 * <th>Values</th>
	 * </tr>
	 * <thead> <tbody>
	 * <tr>
	 * <td>b2b1</td>
	 * <td>00: No PoR reply to the Sending Entity (SE)<br>
	 * 01: PoR required to be sent to the SE<br>
	 * 10: PoR required only when an error has occured<br>
	 * 11: Reserved</td>
	 * </tr>
	 * <tr>
	 * <td>b4b3</td>
	 * <td>00: No security applied to PoR response to SE<br>
	 * 01: PoR response with simple RC applied to it<br>
	 * 10: PoR response with CC applied to it<br>
	 * 11: PoR response with DS applied to it<br>
	 * </tr>
	 * <tr>
	 * <td>b5</td>
	 * <td>0 : PoR response shall not be ciphered<br>
	 * 1 : PoR response shall be ciphered<br>
	 * </tr>
	 * <tr>
	 * <td>b6</td>
	 * <td>0 : PoR response shall be sent using SMS-DELIVER-REPORT <br>
	 * 1 : PoR response shall be sent using SMS-SUBMIT<br>
	 * </tr>
	 * <tr>
	 * <td>b8b7</td>
	 * <td>Reserved (set to zero and ignored by RE)<br>
	 * </tr>
	 * </tbody>
	 * </table>
	 * 
	 * @param spi
	 *            - byte[2].
	 * @throws IllegalArgumentException
	 *             if <strong>spi</strong> length is not 2.
	 */
	void setSPI(byte[] spi) throws IllegalArgumentException;

	/**
	 * Returns transformation name used for signing.
	 * 
	 * @return transformation name
	 */
	String getSignatureAlgorithm();

	/**
	 * Sets transformation name used for signing. Can be in short, e.g. DESMac,
	 * or long(with mode), e.g. DESedeMac/CFB8, form.
	 * 
	 * @param name
	 *            - transformation name.
	 */
	void setSignatureAlgorithm(String name);

	/**
	 * Returns transformation name used for ciphering.
	 * 
	 * @return transformation name
	 */
	String getCipheringAlgorithm();

	/**
	 * Sets transformation name used for ciphering. Can be in short, e.g. DES,
	 * or long(with mode and padding), e.g. DESede/CBC/ZeroBytePadding, form.
	 * 
	 * @param name
	 *            - transformation name.
	 */
	void setCipheringAlgorithm(String name);

	/**
	 * 
	 * @return
	 */
	SecurityBytesType getSecurityBytesType();

	void setSecurityBytesType(SecurityBytesType securityBytesType);
}
