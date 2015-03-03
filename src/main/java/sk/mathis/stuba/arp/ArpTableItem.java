/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.arp;

import java.util.Date;
import sk.mathis.stuba.equip.PacketReceiver;

/**
 *
 * @author martinhudec
 */
public class ArpTableItem {

    private PacketReceiver port; 
    private byte[] ipAddress; 
    private byte[] macAddress; 
    private  Date timeOfAdd;
    
    public ArpTableItem(PacketReceiver port, byte[] ipAddress, byte[] macAddress) {
        this.port = port; 
        this.ipAddress =ipAddress; 
        this.macAddress = macAddress; 
        timeOfAdd = new Date();
    }

    public byte[] getIpAddress() {
        return ipAddress;
    }

    public byte[] getMacAddress() {
        return macAddress;
    }

    public PacketReceiver getPort() {
        return port;
    }

    public Date getTimeOfAdd() {
        return timeOfAdd;
    }
     public void updateTime(){
         timeOfAdd = new Date();
     }
}
