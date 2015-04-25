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
        while (true) {
            while (!arpBuffer.isEmpty()) {
                Packet pckt = arpBuffer.poll();
               // if (Arrays.equals(pckt.getPort().getMacAddressByte(), pckt.getFrame().getSrcMacAddress())) {
                //    break;
                //}

                System.out.println("Dostal som ARP na " + pckt.getPort().getPortName() + " " + pckt.getFrame().getFrameType());

                if (pckt.getFrame().getIsArp()) {
                    if (pckt.getFrame().getArpParser().getOperationType().equalsIgnoreCase("arp-request")) {
                        System.out.println("ARP REQUEST NA " + pckt.getPort().getPortName());
                        byte[] arpReply = PacketGenerator.arpReply(pckt.getPort().getIpAddressByte(), pckt.getFrame().getArpParser().getSourceIPbyte(), pckt.getPort().getMacAddressByte(), pckt.getFrame().getArpParser().getSourceMACbyte());
                        pckt.getPcap().sendPacket(arpReply);
                    } else {
                        logger.info("dostal som REPLY arp pre mna " + pckt.getArpSourceIP().toString() );
                        arpTable.addOrUpdateItem(new ArpTableItem(pckt.getPort(), pckt.getArpSourceIP(), pckt.getFrame().getSrcMacAddress()));
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
