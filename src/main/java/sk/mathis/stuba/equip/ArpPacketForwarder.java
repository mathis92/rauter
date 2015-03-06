/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import java.util.Arrays;
import java.util.List;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.analysers.Analyser;
import sk.mathis.stuba.analysers.Frame;
import sk.mathis.stuba.arp.ArpTable;
import sk.mathis.stuba.arp.ArpTableItem;

/**
 *
 * @author martinhudec
 */
public class ArpPacketForwarder implements Runnable {

    private Queue<Packet> arpBuffer;
    private PacketSender sender;
    // private Queue<Packet> 
    ArpTable arpTable;
    //private List<PacketReceiver> receiverList;
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(PacketForwarder.class);

    public ArpPacketForwarder(Queue<Packet> arpBuffer, ArpTable arpTable) {
        this.arpBuffer = arpBuffer;
        this.arpTable = arpTable;

    }

    @Override
    public void run() {
      //  logger.info("Zapol som arp packet Forwarder");
        while (true) {
            while (!arpBuffer.isEmpty()) {
                Packet pckt = arpBuffer.poll();
                // System.out.println(pckt.getPort().getPortName() + " " + frame.getFrameType());
                if (pckt.getFrame().getIsArp()) {
                  //  logger.info("arp destination ip" + DataTypeHelper.ipAdressConvertor(pckt.getFrame().getArpParser().getDestinationIPbyte()) + " arp source  ip" + DataTypeHelper.ipAdressConvertor(pckt.getFrame().getArpParser().getSourceIPbyte()) + " " + pckt.getFrame().getArpParser().getOperationType());
                    if (pckt.getFrame().getArpParser().getOperationType().equalsIgnoreCase("arp-request")) {
               //         logger.info("dostal som request arp pre mna ");
                        byte[] arpReply = PacketGenerator.arpReply(pckt.getPort().getIpAddress(), pckt.getFrame().getArpParser().getSourceIPbyte(), pckt.getPort().getMacAddress(), pckt.getFrame().getArpParser().getSourceMACbyte());
                        pckt.getPcap().sendPacket(arpReply);
                        //System.out.println("ARP TABLE = " + arpTable);
                        //arpTable.addOrUpdateItem(new ArpTableItem(pckt.getPort(), pckt.getFrame().getArpParser().getSourceIPbyte(), pckt.getFrame().getSrcMacAddress()));
                        //arpTable.updateItemTime(pckt.getFrame().getArpParser().getSourceIPbyte(), pckt.getFrame().getSrcMacAddress(), pckt.getPort());
                    } else {
                        // arpTable.
              //          logger.info("dostal som REPLY arp pre mna ");
                        arpTable.addOrUpdateItem(new ArpTableItem(pckt.getPort(), pckt.getFrame().getArpParser().getSourceIPbyte(), pckt.getFrame().getSrcMacAddress()));
                    }
                }
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException ex) {
                Logger.getLogger(PacketForwarder.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
}
