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
import sk.mathis.stuba.equip.Packet;
import sk.mathis.stuba.equip.PacketGenerator;
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

    public void addOrUpdateItem(ArpTableItem item) {
  //      System.out.println("volam add or update item ");
        boolean contains = false;
        ArpTableItem atItem = null;

        for (ArpTableItem tmp : arpTableList) {
            if (Arrays.equals(tmp.getIpAddress(), item.getIpAddress()) && tmp.getPort().getPortName().equals(item.getPort().getPortName())) {
                contains = true;
                atItem = tmp;
                break;
            }
        }
        if (contains) {
//            System.out.println("NASIEL SOM ZAZNAM V ARP TABULKE IDEM UPDATOVAT TIME");
            atItem.updateTime();
            atItem.storeMacAddress(item.getMacAddress());
        } else {
            arpTableList.add(item);
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

    public ArpTableItem resolveArp(Packet packet) {
        ArpTableItem item = null;
        for (ArpTableItem arpItem : arpTableList) {
            if (Arrays.equals(arpItem.getIpAddress(), packet.getFrame().getIpv4parser().getSourceIPbyte())) {
                item = arpItem;
            }
        }
       // System.out.println("resolveArp " + item);
        if (item == null) {
            ArpTableItem newArpTableItem = new ArpTableItem(packet.getPort(), packet.getFrame().getIpv4parser().getSourceIPbyte(), null);
            arpTableList.add(newArpTableItem);
            byte[] arpRequest = PacketGenerator.arpRequest(packet.getPort().getIpAddress(), packet.getFrame().getIpv4parser().getSourceIPbyte(), packet.getPort().getMacAddress(), DataTypeHelper.broadcastMacAddr());
            packet.getPcap().sendPacket(arpRequest);
        //    System.out.println("poslal som arpRequest a cakam ");
            try {
                synchronized (newArpTableItem.getArpRequestLock()) {
                    newArpTableItem.getArpRequestLock().wait(2000);
                    item = newArpTableItem;
                }
            } catch (InterruptedException ex) {
                Logger.getLogger(ArpTable.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return item;
    }

    public void checkTime() {

        for (Iterator<ArpTableItem> atItem = arpTableList.iterator(); atItem.hasNext();) {
            currentTime = new Date();
            ArpTableItem item = atItem.next();
            if ((currentTime.getTime() - item.getTimeOfAdd().getTime()) > 20000) {
                atItem.remove();
          //      System.out.println("ITEM REMOVED");
                // System.out.println("ipAddress " + DataTypeHelper.ipAdressConvertor(item.getIpAddress()) + " macAddress " + DataTypeHelper.macAdressConvertor(item.getMacAddress()) + " port " + item.getPort().getPortName() + " time " + (item.getTimeOfAdd().getTime() - new Date().getTime()));
            }
        }
    }

    public void updateItemTime(ArpTableItem item) {
        currentTime = new Date();
        item.updateTime();
        item.storeMacAddress(item.getMacAddress());
        /*if (Arrays.equals(item.getIpAddress(), item.getIpAddress()) && Arrays.equals(item.getMacAddress(), item.getMacAddress()) && !item.getPort().getPortName().equals(item.getPort().getPortName())) {
         arpTableList.clear();
         }*/
    }

    public List<ArpTableItem> getArpTableList() {
        return arpTableList;
    }
    
    
}
