//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.10.29 at 04:55:09 PM CET 
//


package edu.yale.tp.cas;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ProxySuccessType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ProxySuccessType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="proxyTicket" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ProxySuccessType", propOrder = {
    "proxyTicket"
})
public class ProxySuccessType {

    @XmlElement(required = true)
    protected String proxyTicket;

    /**
     * Default no-arg constructor
     * 
     */
    public ProxySuccessType() {
        super();
    }

    /**
     * Fully-initialising value constructor
     * 
     */
    public ProxySuccessType(final String proxyTicket) {
        this.proxyTicket = proxyTicket;
    }

    /**
     * Gets the value of the proxyTicket property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getProxyTicket() {
        return proxyTicket;
    }

    /**
     * Sets the value of the proxyTicket property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setProxyTicket(String value) {
        this.proxyTicket = value;
    }

}
