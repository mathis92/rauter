/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.routingTable;

import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.PacketReceiver;

/**
 *
 * @author martinhudec
 */
public class RoutingTableItem {
    byte[] destinationNetwork; 
    byte[] netMask; 
    String cidrRange;
    byte[] gateway; 
    PacketReceiver port; 
    Integer administrativeDistance; 
    String type; 
    byte[] oldInterface;

    public RoutingTableItem(byte[] destinationNetwork, byte[] netMask, byte[] gateway, PacketReceiver port, Integer administrativeDistance, String type) {
        this.destinationNetwork = destinationNetwork;
        this.netMask = netMask;
        this.cidrRange = DataTypeHelper.ipAdressConvertor(destinationNetwork)+"/"+DataTypeHelper.convertNetmaskToCIDR(netMask);
        this.gateway = gateway;
        this.port = port;
        this.administrativeDistance = administrativeDistance;
        this.type = type; 
    }

    public Integer getAdministrativeDistance() {
        return administrativeDistance;
    }

    public byte[] getDestinationNetwork() {
        return destinationNetwork;
    }

    public byte[] getGateway() {
        return gateway;
    }

    public byte[] getNetMask() {
        return netMask;
    }

    public PacketReceiver getPort() {
        return port;
    }

    public String getCidrRange() {
        return cidrRange;
    }


    public String getType() {
        return type;
    }
    public void updateRouteData(byte[] destinationNetwork, byte[] netMask, byte[] gateway, PacketReceiver port, Integer administrativeDistance, String type) {
        this.destinationNetwork = destinationNetwork;
        this.netMask = netMask;
        this.gateway = gateway;
        this.port = port;
        this.cidrRange = DataTypeHelper.ipAdressConvertor(destinationNetwork)+"/"+DataTypeHelper.convertNetmaskToCIDR(netMask);
        this.administrativeDistance = administrativeDistance;
        this.type = type; 
    }
    
    
}
