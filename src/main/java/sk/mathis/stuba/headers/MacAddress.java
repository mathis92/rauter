/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.headers;

import sk.mathis.stuba.equip.DataTypeHelper;

/**
 *
 * @author martinhudec
 */
public class MacAddress {

    byte[] macByte;

    public MacAddress(byte[] macByte) {
        this.macByte = macByte;
    }

    public byte[] getMacByte() {
        return macByte;
    }

    @Override
    public String toString() {
        return DataTypeHelper.macAdressConvertor(macByte);
    }

    
    
}
