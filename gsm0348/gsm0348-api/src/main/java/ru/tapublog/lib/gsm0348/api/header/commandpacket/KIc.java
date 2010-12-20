package ru.tapublog.lib.gsm0348.api.header.commandpacket;
import ru.tapublog.lib.gsm0348.api.header.commandpacket.ciphering.GSM0348CipheringAlgorithmMode;
/**
 * @author Victor Platov
 */
public interface KIc
{
	GSM0348AlgorithmImplementation getAlgorithmImplementation();
	GSM0348CipheringAlgorithmMode getCipheringAlgorithmMode();
	byte getKeySetId();
}
