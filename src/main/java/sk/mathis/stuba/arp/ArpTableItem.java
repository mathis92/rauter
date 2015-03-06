/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.arp;

import java.util.Arrays;
import java.util.Date;
import java.util.Objects;
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.PacketReceiver;

/**
 *
 * @author martinhudec
 */
public class ArpTableItem {

    private PacketReceiver port;
    private byte[] ipAddress;
    private byte[] macAddress;
    private Date timeOfAdd;
    private final Object arpRequestLock = new Object();

    public ArpTableItem(PacketReceiver port, byte[] ipAddress, byte[] macAddress) {
        this.port = port;
        this.ipAddress = ipAddress;
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

    public void updateTime() {
        timeOfAdd = new Date();
    }

    public Object getArpRequestLock() {
        return arpRequestLock;
    }

    public void storeMacAddress(byte[] macAddress) {
        this.macAddress = macAddress;
        this.timeOfAdd = new Date();
      //  System.out.println("zapisal som novu MAC adresu do mac tabulky " + DataTypeHelper.macAdressConvertor(macAddress));

        synchronized (this.arpRequestLock) {
            this.arpRequestLock.notifyAll();
        
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ArpTableItem other = (ArpTableItem) obj;
        if (!Objects.equals(this.port, other.port)) {
            return false;
        }
        if (!Arrays.equals(this.ipAddress, other.ipAddress)) {
            return false;
        }
        if (!Arrays.equals(this.macAddress, other.macAddress)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 71 * hash + Objects.hashCode(this.port);
        hash = 71 * hash + Arrays.hashCode(this.ipAddress);
        hash = 71 * hash + Arrays.hashCode(this.macAddress);

        return hash;
    }
}
