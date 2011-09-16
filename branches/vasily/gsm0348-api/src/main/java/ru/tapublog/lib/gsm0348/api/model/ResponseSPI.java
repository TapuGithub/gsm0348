//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-833 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2011.09.09 at 04:14:20 PM MSD 
//


package ru.tapublog.lib.gsm0348.api.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ResponseSPI complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ResponseSPI">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;all>
 *         &lt;element name="PoRProtocol" type="{ru.tapublog.lib.gsm0348}PoRProtocol"/>
 *         &lt;element name="PoRMode" type="{ru.tapublog.lib.gsm0348}PoRMode"/>
 *         &lt;element name="PoRCertificateMode" type="{ru.tapublog.lib.gsm0348}CertificationMode"/>
 *         &lt;element name="Ciphered" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *       &lt;/all>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ResponseSPI", propOrder = {

})
public class ResponseSPI {

    @XmlElement(name = "PoRProtocol", required = true)
    protected PoRProtocol poRProtocol;
    @XmlElement(name = "PoRMode", required = true)
    protected PoRMode poRMode;
    @XmlElement(name = "PoRCertificateMode", required = true)
    protected CertificationMode poRCertificateMode;
    @XmlElement(name = "Ciphered")
    protected boolean ciphered;

    public void setValue(byte responseByte) {
        switch((byte)(responseByte&0x03)) {
            case 0:
                poRMode = PoRMode.NO_REPLY;
                break;
            case 1:
                poRMode = PoRMode.REPLY_ALWAYS;
                break;
            case 2:
                poRMode = PoRMode.REPLY_WHEN_ERROR;
                break;
            case 3:
                poRMode = PoRMode.RESERVED;
                break;
        }

        switch((byte)((responseByte>>2)&0x03)) {
            case 0:
                poRCertificateMode = CertificationMode.NO_SECURITY;
                break;
            case 1:
                poRCertificateMode = CertificationMode.RC;
                break;
            case 2:
                poRCertificateMode = CertificationMode.CC;
                break;
            case 3:
                poRCertificateMode = CertificationMode.DS;
                break;
        }
    
        ciphered = (responseByte&0x10)!=0;
        
        switch((byte)((responseByte>>5)&0x01)) {
            case 0:
                poRProtocol = PoRProtocol.SMS_DELIVER_REPORT;
                break;
            case 1:
                poRProtocol = PoRProtocol.SMS_SUBMIT;
                break;
        }
    }
    
    public byte getValue() {
        byte responseByte = 0;
        
        switch(poRMode){
            case NO_REPLY:
                //responseByte |= 0x00;
                break;
            case REPLY_ALWAYS:
                responseByte |= 0x01;
                break;
            case REPLY_WHEN_ERROR:
                responseByte |= 0x02;
                break;
            case RESERVED:
                responseByte |= 0x03;
                break;
        }
        
        switch(poRCertificateMode){
            case NO_SECURITY:
                //responseByte |= 0x00<<2;
                break;
            case RC:
                responseByte |= 0x01<<2;
                break;
            case CC:
                responseByte |= 0x02<<2;
                break;
            case DS:
                responseByte |= 0x03<<2;
                break;
        }
        
        if(ciphered)
            responseByte |= 0x10;

        switch(poRProtocol){
            case SMS_DELIVER_REPORT:
                //responseByte |= 0x00<<5;
                break;
            case SMS_SUBMIT:
                responseByte |= 0x01<<5;
                break;
        }
        return responseByte;
    }

    /**
     * Gets the value of the poRProtocol property.
     * 
     * @return
     *     possible object is
     *     {@link PoRProtocol }
     *     
     */
    public PoRProtocol getPoRProtocol() {
        return poRProtocol;
    }

    /**
     * Sets the value of the poRProtocol property.
     * 
     * @param value
     *     allowed object is
     *     {@link PoRProtocol }
     *     
     */
    public void setPoRProtocol(PoRProtocol value) {
        this.poRProtocol = value;
    }

    /**
     * Gets the value of the poRMode property.
     * 
     * @return
     *     possible object is
     *     {@link PoRMode }
     *     
     */
    public PoRMode getPoRMode() {
        return poRMode;
    }

    /**
     * Sets the value of the poRMode property.
     * 
     * @param value
     *     allowed object is
     *     {@link PoRMode }
     *     
     */
    public void setPoRMode(PoRMode value) {
        this.poRMode = value;
    }

    /**
     * Gets the value of the poRCertificateMode property.
     * 
     * @return
     *     possible object is
     *     {@link CertificationMode }
     *     
     */
    public CertificationMode getPoRCertificateMode() {
        return poRCertificateMode;
    }

    /**
     * Sets the value of the poRCertificateMode property.
     * 
     * @param value
     *     allowed object is
     *     {@link CertificationMode }
     *     
     */
    public void setPoRCertificateMode(CertificationMode value) {
        this.poRCertificateMode = value;
    }

    /**
     * Gets the value of the ciphered property.
     * 
     */
    public boolean isCiphered() {
        return ciphered;
    }

    /**
     * Sets the value of the ciphered property.
     * 
     */
    public void setCiphered(boolean value) {
        this.ciphered = value;
    }

	@Override
	public int hashCode()
	{
		final int prime = 31;
		int result = 1;
		result = prime * result + (ciphered ? 1231 : 1237);
		result = prime * result + ((poRCertificateMode == null) ? 0 : poRCertificateMode.hashCode());
		result = prime * result + ((poRMode == null) ? 0 : poRMode.hashCode());
		result = prime * result + ((poRProtocol == null) ? 0 : poRProtocol.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof ResponseSPI))
			return false;
		ResponseSPI other = (ResponseSPI) obj;
		if (ciphered != other.ciphered)
			return false;
		if (poRCertificateMode != other.poRCertificateMode)
			return false;
		if (poRMode != other.poRMode)
			return false;
		if (poRProtocol != other.poRProtocol)
			return false;
		return true;
	}

	@Override
	public String toString()
	{
		StringBuilder builder = new StringBuilder();
		builder.append("ResponseSPI [poRProtocol=");
		builder.append(poRProtocol);
		builder.append(", poRMode=");
		builder.append(poRMode);
		builder.append(", poRCertificateMode=");
		builder.append(poRCertificateMode);
		builder.append(", ciphered=");
		builder.append(ciphered);
		builder.append("]");
		return builder.toString();
	}

}
