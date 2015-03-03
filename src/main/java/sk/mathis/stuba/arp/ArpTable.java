/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.arp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.PacketReceiver;

/**
 *
 * @author martinhudec
 */
public class ArpTable implements Runnable {

    private List<ArpTableItem> arpTableList;
    Date currentTime;

    public ArpTable() {
        arpTableList = new ArrayList<>();
    }

    public void addItem(ArpTableItem item) {
        arpTableList.add(item);
        for (ArpTableItem atItem : arpTableList) {
            System.out.println("ipAddress " + DataTypeHelper.ipAdressConvertor(atItem.getIpAddress()) + " macAddress " + DataTypeHelper.macAdressConvertor(atItem.getMacAddress()) + " port " + atItem.getPort().getPortName() + " time " + (atItem.getTimeOfAdd().getTime() - new Date().getTime()));
        }
    }

    @Override
    public void run() {
        while (true) {
            checkTime();
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                Logger.getLogger(ArpTable.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void checkTime() {
        for (ArpTableItem atItem : arpTableList) {
            System.out.println("ipAddress " + DataTypeHelper.ipAdressConvertor(atItem.getIpAddress()) + " macAddress " + DataTypeHelper.macAdressConvertor(atItem.getMacAddress()) + " port " + atItem.getPort().getPortName() + " time " + (atItem.getTimeOfAdd().getTime() - new Date().getTime()));
        }
        for (Iterator<ArpTableItem> atItem = arpTableList.iterator(); atItem.hasNext();) {
            currentTime = new Date();
            ArpTableItem item = atItem.next();
            if ((currentTime.getTime() - item.getTimeOfAdd().getTime()) > 100000) {
                atItem.remove();
            }
        }
    }

    public void updateItemTime(byte[] ipAddress, byte[] macAddress, PacketReceiver port) {
        int found = 0;
        for (Iterator<ArpTableItem> atItem = arpTableList.iterator(); atItem.hasNext();) {
            currentTime = new Date();
            ArpTableItem item = atItem.next();
            if (Arrays.equals(item.getIpAddress(), ipAddress) && Arrays.equals(item.getMacAddress(), macAddress) && item.getPort().getPortName().equals(port.getPortName())) {
                found = 1;
                item.updateTime();
            }
            if (Arrays.equals(item.getIpAddress(), ipAddress) && Arrays.equals(item.getMacAddress(), macAddress) && !item.getPort().getPortName().equals(port.getPortName())) {
                arpTableList.clear();
            }
        }
        if (found == 0) {
            addItem(new ArpTableItem(port, ipAddress, macAddress));
        }
    }
}
