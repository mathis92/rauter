/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.analysers;

import java.util.Arrays;
import sk.mathis.stuba.equip.DataTypeHelper;

/**
 *
 * @author martinhudec
 */
public class RipItem {

    byte[] addressFamily;
    byte[] routeTag;
    byte[] ipv4Address;
    byte[] subnetMask;
    byte[] nextHop;
    byte[] metric;

    public RipItem(byte[] addressFamily, byte[] routeTag, byte[] ipv4Address, byte[] subnetMask, byte[] nextHop, byte[] metric) {
        this.addressFamily = addressFamily;
        this.routeTag = routeTag;
        this.ipv4Address = ipv4Address;
        this.subnetMask = subnetMask;
        this.nextHop = nextHop;
        if(Arrays.equals(nextHop, DataTypeHelper.ipAddressToByteFromString("0.0.0.0"))){
            
        }
        this.metric = metric;
       // System.out.println("AddressFamily " + DataTypeHelper.toInt(addressFamily));
        //System.out.println("routeTag " + DataTypeHelper.toInt(routeTag));
        //System.out.println("ipv4Address " + DataTypeHelper.ipAdressConvertor(ipv4Address));
        //System.out.println("subnetMask " + DataTypeHelper.ipAdressConvertor(subnetMask));
        //System.out.println("nextHop " + DataTypeHelper.ipAdressConvertor(nextHop));
        //System.out.println("metric " + DataTypeHelper.toInt(metric));

    }

    public byte[] getSubnetMask() {
        return subnetMask;
    }

    public byte[] getRouteTag() {
        return routeTag;
    }

    public byte[] getNextHop() {
        return nextHop;
    }

    public byte[] getMetric() {
        return metric;
    }

    public byte[] getIpv4Address() {
        return ipv4Address;
    }

    public byte[] getAddressFamily() {
        return addressFamily;
    }

}
