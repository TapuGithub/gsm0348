package org.opentelecoms.gsm0348.impl.coders;

import org.opentelecoms.gsm0348.api.Util;
import org.opentelecoms.gsm0348.api.model.ResponsePacketStatus;
import org.opentelecoms.gsm0348.impl.CodingException;

public class ResponsePacketStatusCoder {
  public static byte decode(ResponsePacketStatus respStatus) throws CodingException {
    switch (respStatus) {
      case POR_OK:
        return 0;
      case RC_CC_DS_FAILED:
        return 1;
      case CNTR_LOW:
        return 2;
      case CNTR_HIGH:
        return 3;
      case CNTR_BLOCKED:
        return 4;
      case CIPHERING_ERROR:
        return 5;
      case UNIDENTIFIED_SECURITY_ERROR:
        return 6;
      case INSUFFICIENT_MEMORY:
        return 7;
      case MORE_TIME:
        return 8;
      case TAR_UNKNOWN:
        return 9;
      case INSUFFICIENT_SECURITY_LEVEL:
        return 10;
      default:
        throw new CodingException("Cannot code " + respStatus);
    }
  }

  public static ResponsePacketStatus encode(byte respStatus) throws CodingException {
    switch (respStatus) {
      case 0:
        return ResponsePacketStatus.POR_OK;
      case 1:
        return ResponsePacketStatus.RC_CC_DS_FAILED;
      case 2:
        return ResponsePacketStatus.CNTR_LOW;
      case 3:
        return ResponsePacketStatus.CNTR_HIGH;
      case 4:
        return ResponsePacketStatus.CNTR_BLOCKED;
      case 5:
        return ResponsePacketStatus.CIPHERING_ERROR;
      case 6:
        return ResponsePacketStatus.UNIDENTIFIED_SECURITY_ERROR;
      case 7:
        return ResponsePacketStatus.INSUFFICIENT_MEMORY;
      case 8:
        return ResponsePacketStatus.MORE_TIME;
      case 9:
        return ResponsePacketStatus.TAR_UNKNOWN;
      case 10:
        return ResponsePacketStatus.INSUFFICIENT_SECURITY_LEVEL;
      default:
        throw new CodingException("Cannot decode response packet status with id=" + Util.toHex(respStatus));
    }
  }
}
