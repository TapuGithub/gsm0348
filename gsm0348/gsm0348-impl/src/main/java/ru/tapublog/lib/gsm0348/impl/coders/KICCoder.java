package ru.tapublog.lib.gsm0348.impl.coders;

import static ru.tapublog.lib.gsm0348.api.model.AlgorithmImplementation.AES;
import static ru.tapublog.lib.gsm0348.api.model.AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES;
import static ru.tapublog.lib.gsm0348.api.model.AlgorithmImplementation.DES;
import static ru.tapublog.lib.gsm0348.api.model.AlgorithmImplementation.PROPRIETARY_IMPLEMENTATIONS;

import ru.tapublog.lib.gsm0348.api.model.AlgorithmImplementation;
import ru.tapublog.lib.gsm0348.api.model.CipheringAlgorithmMode;
import ru.tapublog.lib.gsm0348.api.model.KIC;
import ru.tapublog.lib.gsm0348.impl.CodingException;
import ru.tapublog.lib.gsm0348.impl.Util;

public class KICCoder
{
	public static byte decode(KIC kic) throws CodingException
	{
		int algImpl = 0;
		int algMode = 0;
		byte keysetID = kic.getKeysetID();
		
		if(keysetID  < 0 && keysetID > 0xF)
			throw new CodingException("Cannot decode KIC. KIC keySetID cannot be <0 and >15");
		
		switch (kic.getAlgorithmImplementation())
		{
			case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
				algImpl = 0;
				break;
			case DES:
				algImpl = 1;
				break;
			case AES:
				algImpl = 2;
				break;
			case PROPRIETARY_IMPLEMENTATIONS:
				algImpl = 3;
				break;
		}
		
		switch (kic.getCipheringAlgorithmMode())
		{
			case DES_CBC:
			case AES_CBC:
				algMode = 0;
				break;
			case TRIPLE_DES_CBC_2_KEYS:
				algMode = 1;
				break;
			case TRIPLE_DES_CBC_3_KEYS:
				algMode = 2;
				break;
			case DES_ECB:
				algMode = 3;
				break;
		}
		
		byte result = (byte)(algImpl + (algMode << 2) + (keysetID << 4));
		
		return result;
	}

	public static KIC encode(byte kic) throws CodingException
	{
		KIC result = new KIC();

		final int algImpl = kic & 0x3;
		final int algMode = (kic & 0xC) >> 2;
		final byte keysetID = (byte) ((kic & 0xF0) >>> 4);

		AlgorithmImplementation resultAlgImpl = null;
		CipheringAlgorithmMode resultAlgMode = null;
		switch (algImpl)
		{
			case 0:
				resultAlgImpl = ALGORITHM_KNOWN_BY_BOTH_ENTITIES;
				switch (algMode)
				{
					case 0:
						resultAlgMode = CipheringAlgorithmMode.DES_CBC;
						break;
					case 1:
						resultAlgMode = CipheringAlgorithmMode.TRIPLE_DES_CBC_2_KEYS;
						break;
					case 2:
						resultAlgMode = CipheringAlgorithmMode.TRIPLE_DES_CBC_3_KEYS;
						break;
					case 3:
						resultAlgMode = CipheringAlgorithmMode.DES_ECB;
						break;
					default:
						throw new CodingException("Cannot encode KIC(raw=" + Util.toHex(kic) + "). No such DES algorithm mode(raw=" + Integer.toHexString(algMode));
				}
				break;
			case 1:
				resultAlgImpl = DES;
				switch (algMode)
				{
					case 0:
						resultAlgMode = CipheringAlgorithmMode.DES_CBC;
						break;
					case 1:
						resultAlgMode = CipheringAlgorithmMode.TRIPLE_DES_CBC_2_KEYS;
						break;
					case 2:
						resultAlgMode = CipheringAlgorithmMode.TRIPLE_DES_CBC_3_KEYS;
						break;
					case 3:
						resultAlgMode = CipheringAlgorithmMode.DES_ECB;
						break;
					default:
						throw new CodingException("Cannot encode KIC(raw=" + Util.toHex(kic) + "). No such DES algorithm mode(raw=" + Integer.toHexString(algMode));
				}
				break;
			case 2:
				resultAlgImpl = AES;
				switch (algMode)
				{
					case 0:
						resultAlgMode = CipheringAlgorithmMode.AES_CBC;
						break;
					default:
						throw new CodingException("Cannot encode KIC(raw=" + Util.toHex(kic) + "). No such AES algorithm mode(raw=" + Integer.toHexString(algMode));
				}
				break;
			case 3:
				resultAlgImpl = PROPRIETARY_IMPLEMENTATIONS;
				break;

			default:
				throw new CodingException("Cannot encode KIC(raw=" + Util.toHex(kic) + "). No such algorithm implemetation(raw="
						+ Integer.toHexString(algImpl));
		}
		
		if(keysetID  < 0 && keysetID > 0xF)
			throw new CodingException("Cannot encode KIC(raw=" + Util.toHex(kic) + "). KIC keySetID cannot be <0 and >15");
		
		result.setAlgorithmImplementation(resultAlgImpl);
		result.setCipheringAlgorithmMode(resultAlgMode);
		result.setKeysetID(keysetID);
		
		return result;
	}
}
