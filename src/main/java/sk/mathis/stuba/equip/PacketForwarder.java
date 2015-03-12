/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import ak.mathis.stuba.rip.RipManager;
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
    private Queue<Packet> ripBuffer;
    private PacketSender sender;
    private Analyser analyser;
    ArpTable arpTable = null;
    RoutingTable routingTable = null;
    private List<PacketReceiver> receiverList;
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(PacketForwarder.class);

    public PacketForwarder(Queue<Packet> buffer, Queue<Packet> arpBuffer, ArpTable arpTable, List<PacketReceiver> portList, RoutingTable rootingTable) {
        this.buffer = buffer;
        this.analyser = new Analyser();
        this.arpTable = arpTable;
        this.routingTable = rootingTable;
    }

    @Override
    public void run() {
        //System.out.println("Zapol som packet Forwarder");
        while (true) {
            while (!buffer.isEmpty()) {
                Packet pckt = buffer.poll();
                
                if (Arrays.equals(pckt.getPort().getMacAddress(), pckt.getFrame().getSrcMacAddress())) {
                    break;
                }
                
                if (pckt.getFrame().getIsIpv4()) {
                    if (pckt.getFrame().getIpv4parser().getIsIcmp() && pckt.getFrame().getIpv4parser().getIcmpParser().getType() == 8 && pckt.getFrame().getIpv4parser().getIcmpParser().getCode() == 0) {
                        System.out.println("MAM TU REQUEST ICMP from " + pckt.getPort().getPortName());
                    } else if (pckt.getFrame().getIpv4parser().getIsIcmp() && pckt.getFrame().getIpv4parser().getIcmpParser().getType() == 0 && pckt.getFrame().getIpv4parser().getIcmpParser().getCode() == 0) {
                        System.out.println("MAM TU REPLY ICMP from " + pckt.getPort().getPortName());
                    }
                    if (Arrays.equals(pckt.getPort().getIpAddress(), pckt.getFrame().getIpv4parser().getDestinationIPbyte())) {
                        if (pckt.getFrame().getIpv4parser().getIsIcmp() && pckt.getFrame().getIpv4parser().getIcmpParser().getType() == 8 && pckt.getFrame().getIpv4parser().getIcmpParser().getCode() == 0) {

                            ArpTableItem atItem = arpTable.resolveArp(pckt.getPort(), pckt.getFrame().getIpv4parser().getSourceIPbyte());

                            if (atItem != null) {
                                byte[] resolvedMacAddress = atItem.getMacAddress();
                                System.out.println("RESOLVED MAC ADDRESS " + DataTypeHelper.macAdressConvertor(resolvedMacAddress));
                                Packet icmpReply = PacketGenerator.icmpReply(pckt, pckt.getPort().getIpAddress(), pckt.getFrame().getIpv4parser().getSourceIPbyte(), pckt.getPort().getMacAddress(), resolvedMacAddress);
                                System.out.println("NEW ICMP REPLY TO " + DataTypeHelper.ipAdressConvertor(icmpReply.getFrame().getIpv4parser().getDestinationIPbyte()) + " from " + DataTypeHelper.ipAdressConvertor(icmpReply.getFrame().getIpv4parser().getSourceIPbyte()));
                                System.out.println("NEW PACKET MACADDR TO " + DataTypeHelper.macAdressConvertor(icmpReply.getFrame().getDstMacAddress()) + " from " + DataTypeHelper.macAdressConvertor(icmpReply.getFrame().getSrcMacAddress()));
                                System.out.println("GOING TO BE SENT ON " + icmpReply.getPort().getPortName());

                                icmpReply.getPcap().sendPacket(icmpReply.getPacket().getByteArray(0, icmpReply.getPacket().getCaptureHeader().caplen()));

                            } else {
                                try {
                                    throw new ArpException("Arp not resolved");
                                } catch (ArpException ex) {
                                    Logger.getLogger(PacketForwarder.class.getName()).log(Level.SEVERE, null, ex);
                                }
                            }
                        }
                    } else {
                        if (pckt.getFrame().getIpv4parser().getIsIcmp() && pckt.getFrame().getIpv4parser().getIcmpParser().getType() == 8 && pckt.getFrame().getIpv4parser().getIcmpParser().getCode() == 0) {
                            System.out.println("MAM TU REQUEST from " + pckt.getPort().getPortName());
                        } else if (pckt.getFrame().getIpv4parser().getIsIcmp() && pckt.getFrame().getIpv4parser().getIcmpParser().getType() == 0 && pckt.getFrame().getIpv4parser().getIcmpParser().getCode() == 0) {
                            System.out.println("MAM TU REPLY from " + pckt.getPort().getPortName());
                        }

                        System.out.println("\n ");
                        System.out.println("RECEIVED PACKET ON " + pckt.getPort().getPortName() + " FROM " + DataTypeHelper.ipAdressConvertor(pckt.getFrame().getIpv4parser().getSourceIPbyte()) + " to -> " + DataTypeHelper.ipAdressConvertor(pckt.getFrame().getIpv4parser().getDestinationIPbyte()));
                        System.out.println("FROM MAC ADDR " + DataTypeHelper.macAdressConvertor(pckt.getFrame().getSrcMacAddress()) + " to -> " + DataTypeHelper.macAdressConvertor(pckt.getFrame().getDstMacAddress()));

                        RoutingTableItem route = routingTable.resolveRoute(pckt);
                        if (route != null) {
                            System.out.println("route " + route.getCidrRange());
                            ArpTableItem arpTableItem = arpTable.resolveArp(route.getPort(), pckt.getFrame().getIpv4parser().getDestinationIPbyte());

                            // System.out.println("Resolved route to " + DataTypeHelper.ipAdressConvertor(route.getDestinationNetwork()) + " nextHop " + DataTypeHelper.ipAdressConvertor(route.getGateway()) + " port " + arpTableItem.getPort().getPortName() + " destination IP " + DataTypeHelper.ipAdressConvertor(pckt.getFrame().getIpv4parser().getDestinationIPbyte()));
                            if (arpTableItem != null) {
                                System.out.println("Returned ARP destination Mac addr " + DataTypeHelper.macAdressConvertor(arpTableItem.getMacAddress()));
                                byte[] nextHopMacAddress = arpTableItem.getMacAddress();

                                Packet forwardingPacket = PacketGenerator.forwardPacket(pckt, route.getPort().getMacAddress(), nextHopMacAddress);
                                System.out.println("To FORWARDER AS SOURCE" + DataTypeHelper.macAdressConvertor(route.getPort().getMacAddress()) + " AS DEST " + DataTypeHelper.macAdressConvertor(nextHopMacAddress));
                                System.out.println("NEW PACKET TO " + DataTypeHelper.ipAdressConvertor(forwardingPacket.getFrame().getIpv4parser().getDestinationIPbyte()) + " from " + DataTypeHelper.ipAdressConvertor(forwardingPacket.getFrame().getIpv4parser().getSourceIPbyte()));
                                System.out.println("NEW PACKET MACADDR TO " + DataTypeHelper.macAdressConvertor(forwardingPacket.getFrame().getDstMacAddress()) + " from " + DataTypeHelper.macAdressConvertor(forwardingPacket.getFrame().getSrcMacAddress()));
                                System.out.println("GOING TO BE SENT ON " + route.getPort().getPortName());
                                System.out.println(DataTypeHelper.packetToString(pckt));

                                route.getPort().getPcap().sendPacket(forwardingPacket.getPacket().getByteArray(0, forwardingPacket.getPacket().getCaptureHeader().caplen()));
                            }

                        }
                        System.out.println("\n ");
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
