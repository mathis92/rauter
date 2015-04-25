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
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.analysers.Analyser;
import sk.mathis.stuba.analysers.Frame;
import sk.mathis.stuba.arp.ArpTable;
import sk.mathis.stuba.arp.ArpTableItem;
import sk.mathis.stuba.exceptions.ArpException;
import sk.mathis.stuba.headers.IpV4Address;
import sk.mathis.stuba.routingTable.RouteTypeEnum;
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
    private List<Port> portList;
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(PacketForwarder.class);

    public PacketForwarder(Queue<Packet> buffer, Queue<Packet> arpBuffer, ArpTable arpTable, List<Port> portList, RoutingTable rootingTable) {
        this.buffer = buffer;
        this.analyser = new Analyser();
        this.arpTable = arpTable;
        this.routingTable = rootingTable;
        this.portList = portList;
    }

    @Override
    public void run() {
        //System.out.println("Zapol som packet Forwarder");
        while (true) {
            while (!buffer.isEmpty()) {
                Packet pckt = buffer.poll();
                
               // for(Port port : portList){
                    
                 // if(Arrays.equals(pckt.getSrcMac().getMacByte(), pckt.getPortMac().getMacByte())){
                 //       break;
                //  }
                //}
                
                if (pckt.getFrame().getIsIpv4()) {
                    logger.debug("PACKET FORWARDER " + " paket z  " + pckt.getSourceIp() + " paket na " + pckt.getDestinationIP() + " prijaty na interf " + pckt.getPort().getPortName());
                    Port pingPort = null;
                    for(Port port : portList){
                        logger.debug("PORT NAME " + port.getPortName() + " IP " +port.getIpAddress());
                       if (IpV4Address.compareIp(port.getIpAddress(), pckt.getDestinationIP())){
                           pingPort = port;
                       }
                    }
                    if (pingPort != null) {
                        logger.debug("packet pre PORT NA ROUTERI  " + pingPort.getPortName() + " " + pingPort.getIpAddress());
                        if (pckt.getFrame().getIpv4parser().getIsIcmp() && pckt.getFrame().getIpv4parser().getIcmpParser().getType() == 8 && pckt.getFrame().getIpv4parser().getIcmpParser().getCode() == 0) {

                           // RoutingTableItem route = routingTable.resolveRoute(pckt.getDestinationIP().getBytes());
                            RoutingTableItem route = routingTable.resolveRoute(pckt.getSourceIp().getBytes());
//SPRAVIT TOTO ZE TU MA BYT SRC IP ABY SA DALI PINGAT AJ INE PORTY 
                            logger.debug("A--------------------------------------------->");
                            if (route != null) {
                                logger.debug("route destination network" + route.getDestinationNetwork());
                                ArpTableItem arpTableItem;
                                if (route.getType() == RouteTypeEnum.directlyConnectedRoute) {
                                    logger.debug("B--------------------------------------------->");
                                    arpTableItem = arpTable.resolveArp(route.getPort(), null, pckt.getSourceIp());
                                } else {
                                    logger.debug("C--------------------------------------------->");
                                    RoutingTableItem routeDirect = routingTable.resolveRoute(route.getGatewayByte());
                                    ArpTableItem arpTableItemDirect = arpTable.resolveArp(routeDirect.getPort(), route.getGateway(), null);//pckt.getDestinationIP());
                                    arpTableItem = arpTableItemDirect;
                                    route = routeDirect;
                                }

                                if (arpTableItem != null) {
                                    logger.debug("D--------------------------------------------->");
                                    byte[] resolvedMacAddress = arpTableItem.getMacAddressByte();
                                    logger.debug("RESOLVED MAC ADDRESS " + DataTypeHelper.macAdressConvertor(resolvedMacAddress));
                                    logger.debug("resolve arp pckt SOSURCE ip " + DataTypeHelper.ipAdressConvertor(pckt.getFrame().getIpv4parser().getSourceIPbyte()));
                                    Packet icmpReply = PacketGenerator.icmpReply(pckt, pingPort.getIpAddressByte(), pckt.getFrame().getIpv4parser().getSourceIPbyte(), route.getPort().getMacAddressByte(), resolvedMacAddress);
                                    logger.debug("NEW ICMP REPLY TO " + DataTypeHelper.ipAdressConvertor(icmpReply.getFrame().getIpv4parser().getDestinationIPbyte()) + " from " + DataTypeHelper.ipAdressConvertor(icmpReply.getFrame().getIpv4parser().getSourceIPbyte()));
                                    logger.debug("NEW PACKET MACADDR TO " + DataTypeHelper.macAdressConvertor(icmpReply.getFrame().getDstMacAddress()) + " from " + DataTypeHelper.macAdressConvertor(icmpReply.getFrame().getSrcMacAddress()));
                                    logger.debug("GOING TO BE SENT ON " + icmpReply.getPort().getPortName());
                                    logger.debug("PACKET SIZE " + icmpReply.getPacket().getCaptureHeader().caplen());
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
                    
                    } else {
                        logger.debug("E--------------------------------------------->");
                        logger.debug("packet pre FORARDING  " + pckt.getPort().getPortName() + " " + pckt.getPortIp().toString());
                        RoutingTableItem route = routingTable.resolveRoute(pckt.getDestinationIP().getBytes());
                        if (route != null) {
                            logger.debug("F--------------------------------------------->");
                            ArpTableItem arpTableItem;
                            if (route.getType() == RouteTypeEnum.directlyConnectedRoute) {
                                logger.debug("G--------------------------------------------->");
                                logger.debug("Directly connected zaznam z route tabulky " + route.getGateway().toString());
                                logger.debug("odosielam dotaz na arp tabulku port " + route.getPort().getPortName() + " packetsrc " + pckt.getSourceIp().toString());
                                arpTableItem = arpTable.resolveArp(route.getPort(), null, pckt.getDestinationIP());
                            } else {
                                logger.debug("H--------------------------------------------->");
                                logger.debug("Druhy dotaz na route tabulku");
                                RoutingTableItem routeDirect = routingTable.resolveRoute(route.getGatewayByte());
                                logger.debug("odosielam dotaz na arp tabulku port " + routeDirect.getPort().getPortName() + " routeDirectGateway " + routeDirect.getGateway().toString() + " pcktsrc " + pckt.getSourceIp().toString());
                                ArpTableItem arpTableItemDirect = arpTable.resolveArp(routeDirect.getPort(), route.getGateway(), null);// pckt.getDestinationIP());
                                arpTableItem = arpTableItemDirect;
                                route = routeDirect;
                            }
                            // System.out.println("Resolved route to " + DataTypeHelper.ipAdressConvertor(route.getDestinationNetworkBytes()) + " nextHop " + DataTypeHelper.ipAdressConvertor(route.getGateway()) + " port " + arpTableItem.getPort().getPortName() + " destination IP " + DataTypeHelper.ipAdressConvertor(pckt.getFrame().getIpv4parser().getDestinationIPbyte()));
                            if (arpTableItem != null) {
                                logger.debug("I--------------------------------------------->");
                                if (arpTableItem.getMacAddress().getMacByte() != null) {
                                    logger.debug("J--------------------------------------------->");
                                    byte[] nextHopMacAddress = arpTableItem.getMacAddress().getMacByte();
                                    logger.debug("route.getPort " + route.getPort().getMacAddress());
                                    Packet forwardingPacket = PacketGenerator.forwardPacket(pckt, route.getPort().getMacAddressByte(), nextHopMacAddress);
                                    logger.debug("To FORWARDER AS SOURCE" + DataTypeHelper.macAdressConvertor(route.getPort().getMacAddressByte()) + " AS DEST " + DataTypeHelper.macAdressConvertor(nextHopMacAddress));
                                    logger.debug("NEW PACKET TO " + DataTypeHelper.ipAdressConvertor(forwardingPacket.getFrame().getIpv4parser().getDestinationIPbyte()) + " from " + DataTypeHelper.ipAdressConvertor(forwardingPacket.getFrame().getIpv4parser().getSourceIPbyte()));
                                    logger.debug("NEW PACKET MACADDR TO " + DataTypeHelper.macAdressConvertor(forwardingPacket.getFrame().getDstMacAddress()) + " from " + DataTypeHelper.macAdressConvertor(forwardingPacket.getFrame().getSrcMacAddress()));
                                    logger.debug("GOING TO BE SENT ON " + route.getPort().getPortName());
                                    logger.debug(DataTypeHelper.packetToString(pckt));

                                    route.getPort().getPcap().sendPacket(forwardingPacket.getPacket().getByteArray(0, forwardingPacket.getPacket().getCaptureHeader().caplen()));
                                }
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
