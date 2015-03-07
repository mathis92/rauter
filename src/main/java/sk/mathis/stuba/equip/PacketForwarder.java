/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.packet.PcapPacket;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.analysers.Analyser;
import sk.mathis.stuba.analysers.Frame;
import sk.mathis.stuba.arp.ArpTable;
import sk.mathis.stuba.arp.ArpTableItem;
import sk.mathis.stuba.exceptions.ArpException;
import sk.mathis.stuba.routingTable.RoutingTable;
import sk.mathis.stuba.routingTable.RoutingTableItem;

/**
 *
 * @author Mathis
 */
public class PacketForwarder implements Runnable {

    private Queue<Packet> buffer;
    private Queue<Packet> arpBuffer;
    private PacketSender sender;
    private Analyser analyser;
    ArpTable arpTable = null;
    RoutingTable rootingTable = null;
    private List<PacketReceiver> receiverList;
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(PacketForwarder.class);

    public PacketForwarder(Queue<Packet> buffer, Queue<Packet> arpBuffer, ArpTable arpTable, List<PacketReceiver> portList, RoutingTable rootingTable) {
        this.buffer = buffer;
        this.arpBuffer = arpBuffer;
        this.analyser = new Analyser();
        this.arpTable = arpTable;
        this.rootingTable = rootingTable;

    }

    @Override
    public void run() {
        //System.out.println("Zapol som packet Forwarder");
        while (true) {
            while (!buffer.isEmpty()) {
                Packet pckt = buffer.poll();

                // System.out.println(pckt.getPort().getPortName() + " " + frame.getFrameType());
                if (pckt.getFrame().getIsIpv4()) {
                    if (Arrays.equals(pckt.getPort().getIpAddress(), pckt.getFrame().getIpv4parser().getDestinationIPbyte())) {
                        if (pckt.getFrame().getIpv4parser().getIsIcmp() && pckt.getFrame().getIpv4parser().getIcmpParser().getType() == 8 && pckt.getFrame().getIpv4parser().getIcmpParser().getCode() == 0) {

                            ArpTableItem atItem = arpTable.resolveArp(pckt);

                            if (atItem != null) {
                                byte[] resolvedMacAddress = atItem.getMacAddress();

                                Packet icmpReply = PacketGenerator.icmpReply(pckt, pckt.getPort().getIpAddress(), pckt.getFrame().getIpv4parser().getSourceIPbyte(), pckt.getPort().getMacAddress(), resolvedMacAddress);
                                icmpReply.getPcap().sendPacket(icmpReply.getPacket().getByteArray(0, icmpReply.getPacket().getCaptureHeader().caplen()));
                            } else {
                                try {
                                    throw new ArpException("Arp not resolved");
                                } catch (ArpException ex) {
                                    Logger.getLogger(PacketForwarder.class.getName()).log(Level.SEVERE, null, ex);
                                }
                            }
                        }
                    }
                }
                RoutingTableItem route  = rootingTable.resolveRoute(pckt);
                
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException ex) {
                Logger.getLogger(PacketForwarder.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

}
