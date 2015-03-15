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
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.Packet;
import sk.mathis.stuba.equip.PacketForwarder;
import sk.mathis.stuba.equip.PacketGenerator;
import sk.mathis.stuba.equip.PacketReceiver;
import sk.mathis.stuba.headers.IpV4Address;

/**
 *
 * @author martinhudec
 */
public class ArpTable implements Runnable {

    private List<ArpTableItem> arpTableList;
    Date currentTime;
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(ArpTable.class);

    public ArpTable() {
        arpTableList = new ArrayList<>();
    }

    public void addOrUpdateItem(ArpTableItem item) {
        //      System.out.println("volam add or update item ");
        boolean contains = false;
        ArpTableItem atItem = null;

        for (ArpTableItem tmp : arpTableList) {
            if (IpV4Address.compareIp(tmp.getIpAddress(), item.getIpAddress()) && tmp.getPort().getPortName().equals(item.getPort().getPortName())) {
                contains = true;
                atItem = tmp;
                break;
            }
        }
        if (contains) {
//            System.out.println("NASIEL SOM ZAZNAM V ARP TABULKE IDEM UPDATOVAT TIME");
            atItem.updateTime();
            atItem.storeMacAddress(item.getMacAddressByte());
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

    public ArpTableItem resolveArp(PacketReceiver port, IpV4Address ipAddress, IpV4Address pcktIpAddress) {
        logger.debug(port.getPortName() + " port IP " + port.getIpAddress().toString() + " portMAc " + port.getMacAddress().toString() + " ipv4Address " + ipAddress + " pckt src IP " + pcktIpAddress);
        ArpTableItem item = null;
        if (ipAddress == null) {
            //      ipAddress = pckt.getSourceIp();
                ipAddress = pcktIpAddress;
            }

        
        logger.debug("Ip adresa a port do hladania v ARP tabulke " + ipAddress.toString() + " " + port.getPortName());
        for (ArpTableItem arpItem : arpTableList) {
            logger.debug("zaznam v arp tabulke " + DataTypeHelper.ipAdressConvertor(arpItem.getIpAddressByte()));
            if (IpV4Address.compareIp(arpItem.getIpAddress(), ipAddress) && arpItem.getPort().getPortName().equals(port.getPortName())) {
                item = arpItem;
            }
        }
        logger.debug("najdena IP " + item);

        if (item == null) {
            ArpTableItem newArpTableItem = new ArpTableItem(port, ipAddress, null);
            arpTableList.add(newArpTableItem);
            logger.debug("SRC IP " + port.getIpAddress() + " DST IP" + ipAddress);
            byte[] arpRequest = PacketGenerator.arpRequest(port.getIpAddressByte(), ipAddress.getBytes(), port.getMacAddressByte(), DataTypeHelper.broadcastMacAddr());

            port.getPcap().sendPacket(arpRequest);
            logger.debug("posielam ARP REQUEST src ip " + DataTypeHelper.ipAdressConvertor(port.getIpAddressByte()) + " dst ip " + ipAddress.toString() + " src mac " + DataTypeHelper.macAdressConvertor(port.getMacAddressByte()) + " port " + port.getPortName());
            try {
                synchronized (newArpTableItem.getArpRequestLock()) {

                    newArpTableItem.getArpRequestLock().wait(2000);
                    if (newArpTableItem.getMacAddress().getMacByte() != null) {
                        item = newArpTableItem;
                        logger.debug("vratil sa arp Reply s mac addr " + newArpTableItem.getMacAddress().toString());
                    } else {
                        return null;
                    }
                }
            } catch (InterruptedException ex) {
                Logger.getLogger(ArpTable.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else if (item.getMacAddress() == null) {
            logger.debug("ARP ITEM NOT NULL " + item.getIpAddress() + " " + item.getMacAddress() + " " + item.getPort());
            return null;
        }

        return item;
    }

    public void checkTime() {

        for (Iterator<ArpTableItem> atItem = arpTableList.iterator(); atItem.hasNext();) {
            currentTime = new Date();
            ArpTableItem item = atItem.next();
            if ((currentTime.getTime() - item.getTimeOfAdd().getTime()) > 100000) {
                atItem.remove();
                //      System.out.println("ITEM REMOVED");
                // System.out.println("IpV4Address " + DataTypeHelper.ipAdressConvertor(item.getBytes()) + " MacAddress " + DataTypeHelper.macAdressConvertor(item.getMacAddressByte()) + " port " + item.getPort().getPortName() + " time " + (item.getTimeOfAdd().getTime() - new Date().getTime()));
            }
        }
    }

    public void updateItemTime(ArpTableItem item) {
        currentTime = new Date();
        item.updateTime();
        item.storeMacAddress(item.getMacAddressByte());
        /*if (Arrays.equals(item.getBytes(), item.getBytes()) && Arrays.equals(item.getMacAddressByte(), item.getMacAddressByte()) && !item.getPort().getPortName().equals(item.getPort().getPortName())) {
         arpTableList.clear();
         }*/
    }

    public List<ArpTableItem> getArpTableList() {
        return arpTableList;
    }

}
