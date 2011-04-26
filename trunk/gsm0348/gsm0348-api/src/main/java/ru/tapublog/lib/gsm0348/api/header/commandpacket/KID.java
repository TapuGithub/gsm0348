package ru.tapublog.lib.gsm0348.api.header.commandpacket;

import ru.tapublog.lib.gsm0348.api.header.commandpacket.certificate.GSM0348CertificateAlgorithmMode;

/**
 * @author Victor Platov
 */
public interface KID
{
	GSM0348AlgorithmImplementation getAlgorithmImplementation();

	GSM0348CertificateAlgorithmMode getCertificateAlgorithmMode();

	byte getKeySetId();
}
