/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.headers;

import java.util.Arrays;
import sk.mathis.stuba.equip.DataTypeHelper;

/**
 *
 * @author martinhudec
 */
public class IpV4Address {

    byte[] ipAddressByte;

    public IpV4Address(byte[] ipByte) {
        this.ipAddressByte = ipByte;
    }
    public IpV4Address(String ipString){
        fromString(ipString);
    }
    @Override
    public String toString() {
       return DataTypeHelper.ipAdressConvertor(ipAddressByte);
    }

    public byte[] getBytes() {
        return ipAddressByte;
    }

    public void setIpAddressByte(byte[] ipAddressByte) {
        this.ipAddressByte = ipAddressByte;
    }
   
    public void fromString(String ipString){
       ipAddressByte = DataTypeHelper.ipAddressToByteFromString(ipString);
    }
   
    public static boolean compareIp(IpV4Address ip1, IpV4Address ip2){
        return Arrays.equals(ip1.getBytes(), ip2.getBytes());
    }
    public IpV4Address checkRange(byte[] subnetMask){
       
        // System.out.println("IP addr " + DataTypeHelper.ipAdressConvertor(ipAddress) + " MASK " + DataTypeHelper.ipAdressConvertor(subnetMask));
        byte[] network = new byte[4];
        for (int i = 0; i < 4; i++) {
            network[i] = (byte) ((byte) ipAddressByte[i] & (byte) subnetMask[i]);

        }
       // System.out.println("IP addr " + DataTypeHelper.ipAdressConvertor(network));

        return new IpV4Address(network);

    
    }
}
