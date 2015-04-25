/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.router;

import ak.mathis.stuba.rip.RipManager;
import java.io.IOException;
import java.nio.Buffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.arp.ArpTable;
import sk.mathis.stuba.equip.ArpPacketForwarder;
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.Packet;
import sk.mathis.stuba.equip.PacketForwarder;
import sk.mathis.stuba.equip.Port;
import sk.mathis.stuba.routingTable.RoutingTable;

/**
 *
 * @author martinhudec
 */
public class RouterManager {

    List<Port> availiablePorts;
    List<Port> receiverList = null;
    PacketForwarder packetForwarder = null;
    Queue<Packet> packetBuffer;
    Queue<Packet> arpPacketBuffer;
    Queue<Packet> ripPacketBuffer;
    RipManager ripManager;
    ArpTable arpTable;
    RoutingTable routingTable;

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(RouterManager.class);

    public RouterManager() {

        availiablePorts = new ArrayList<>();
        receiverList = new ArrayList<>();
        packetBuffer = new ConcurrentLinkedQueue<>();
        arpPacketBuffer = new ConcurrentLinkedQueue<>();
        ripPacketBuffer = new ConcurrentLinkedQueue<>();
        try {
            DataTypeHelper.scanPortsFile();
            DataTypeHelper.scanProtocolFile();
        } catch (IOException ex) {
            Logger.getLogger(RouterManager.class.getName()).log(Level.SEVERE, null, ex);
        }

        try {
            findDevices();
        } catch (IOException ex) {
            Logger.getLogger(RouterManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        arpTable = new ArpTable();
        routingTable = new RoutingTable(this);
        ripManager = new RipManager(this);

    }

    public void findDevices() throws IOException {
        List<PcapIf> ports = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
        int r = Pcap.findAllDevs(ports, errbuf);
        if (r == Pcap.NOT_OK || ports.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf
                    .toString());
            return;
        }
        int portNum = 0;
        for (PcapIf port : ports) {
            System.out.println(port.getName() + " " + DataTypeHelper.macAdressConvertor(port.getHardwareAddress()));
            availiablePorts.add(new Port(port, packetBuffer, arpPacketBuffer, "fastEthernet 0/" + portNum, arpTable, ripPacketBuffer, ripManager));
            portNum++;
        }
    }

    public void start() {
        // System.out.println("Router manager start");
        logger.info("[RouterManager] Start");
        new Thread(arpTable).start();
        new Thread(ripManager).start();
        new Thread(routingTable).start();
        if (!availiablePorts.isEmpty()) {
            for (Port port : availiablePorts) {
                port.startThread();
            }
            packetForwarder = new PacketForwarder(packetBuffer, arpPacketBuffer, arpTable, availiablePorts, routingTable);
            new Thread(packetForwarder).start();
            Thread thread = new Thread(new ArpPacketForwarder(arpPacketBuffer, arpTable));
            thread.start();
            //ripManager = new RipManager(this);
            //new Thread(ripManager).start();
        }
    }

    public List<Port> getAvailiablePorts() {
        return availiablePorts;
    }

    public ArpTable getArpTable() {
        return arpTable;
    }

    public Queue<Packet> getRipPacketBuffer() {
        return ripPacketBuffer;
    }

    public RipManager getRipManager() {
        return ripManager;
    }

    public RoutingTable getRoutingTable() {
        return routingTable;
    }

}
