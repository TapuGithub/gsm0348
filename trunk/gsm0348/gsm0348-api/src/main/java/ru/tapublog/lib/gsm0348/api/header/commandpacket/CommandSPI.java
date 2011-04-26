package ru.tapublog.lib.gsm0348.api.header.commandpacket;

import ru.tapublog.lib.gsm0348.api.header.commandpacket.certificate.GSM0348CertificateMode;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.synchronization.GSM0348SynchroCounterMode;

/**
 * @author Victor Platov
 */
public interface CommandSPI
{
	GSM0348CertificateMode getCertificateMode();

	GSM0348SynchroCounterMode getSynchroCounterMode();

	boolean isCiphered();
}
