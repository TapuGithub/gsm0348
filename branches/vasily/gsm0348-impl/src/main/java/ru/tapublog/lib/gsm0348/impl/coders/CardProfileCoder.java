/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package ru.tapublog.lib.gsm0348.impl.coders;

import java.util.Arrays;
import ru.tapublog.lib.gsm0348.api.model.CardProfile;
import ru.tapublog.lib.gsm0348.api.model.KIC;
import ru.tapublog.lib.gsm0348.api.model.KID;
import ru.tapublog.lib.gsm0348.api.model.SPI;
import ru.tapublog.lib.gsm0348.impl.CodingException;

/**
 *
 * @author avilov
 */
public class CardProfileCoder {
	private static final int PACKET_LENGHT_SIZE = 2;

	private static final int HEADER_LENGHT_POSITION = 0;
	private static final int HEADER_LENGHT_RESPONSE_POSITION = 2;
	private static final int HEADER_LENGHT_SIZE = 1;

	private static final int SPI_POSITION = 1;
	private static final int SPI_SIZE = 2;

	private static final int KIC_POSITION = 3;
	private static final int KIC_SIZE = 1;

	private static final int KID_POSITION = 4;
	private static final int KID_SIZE = 1;

	private static final int TAR_POSITION = 5;
	private static final int TAR_RESPONSE_POSITION = 3;
	private static final int TAR_SIZE = 3;

	private static final int COUNTERS_POSITION = 8;
	private static final int COUNTERS_RESPONSE_POSITION = 6;
	private static final int COUNTERS_SIZE = 5;

	private static final int PADDING_COUNTER_POSITION = 13;
	private static final int PADDING_COUNTER_RESPONSE_POSITION = 11;
	private static final int PADDING_COUNTER_SIZE = 1;

	private static final int RESPONSE_CODE_RESPONSE_POSITION = 12;
	private static final int RESPONSE_CODE_RESPONSE_SIZE = 1;

	private static final int SIGNATURE_POSITION = 14;
	private static final int SIGNATURE_RESPONSE_POSITION = 13;

    private static final int MINIMUM_COMMAND_PACKET_SIZE = 16;
	private static final int MINIMUM_RESPONSE_PACKET_SIZE = 13;

	private static final int HEADER_SIZE_WITOUT_SIGNATURE = SPI_SIZE + KIC_SIZE + KID_SIZE + TAR_SIZE + COUNTERS_SIZE
			+ PADDING_COUNTER_SIZE;
    
    private static final int HEADER_SIZE_UNCRIPTED = HEADER_LENGHT_SIZE + SPI_SIZE + KIC_SIZE + KID_SIZE + TAR_SIZE;

    public static CardProfile getProfileFromRow(byte[] datarow) throws CodingException {
        CardProfile newCardProfile = new CardProfile();
        
        newCardProfile.setCipheringAlgorithm("");
        newCardProfile.setSignatureAlgorithm("");
        //cardProfile.setSecurityBytesType(SecurityBytesType.WITH_LENGHTS);
        newCardProfile.setTAR(Arrays.copyOfRange(datarow, 2 + TAR_POSITION,
                2 + TAR_POSITION + TAR_SIZE));
        
        KIC kic = KICCoder.encode(datarow[2 + KIC_POSITION]);
        KID kid = KIDCoder.encode(datarow[2 + KID_POSITION]);
        SPI spi = new SPI();
        spi.setCommandSPI(CommandSPICoder.encode(datarow[2 + SPI_POSITION]));
        spi.setResponseSPI(ResponseSPICoder.encode(datarow[2 + SPI_POSITION + 1]));
        
        newCardProfile.setSPI(spi);
        newCardProfile.setKIC(kic);
        newCardProfile.setKID(kid);
        
        return newCardProfile;
    }
}
