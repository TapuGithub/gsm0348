package ru.tapublog.lib.gsm0348.api.header.commandpacket;

import ru.tapublog.lib.gsm0348.api.header.commandpacket.response.GSM0348PoRCertificateMode;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.response.GSM0348PoRMode;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.response.GSM0348PoRProtocol;

public interface ResponseSPI
{
	GSM0348PoRCertificateMode getPoRCertificateMode();

	GSM0348PoRProtocol getPoRProtocol();

	GSM0348PoRMode getPoRMode();

	boolean isPoRCiphered();
}
