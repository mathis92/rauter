/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.router;

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
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.Packet;
import sk.mathis.stuba.equip.PacketForwarder;
import sk.mathis.stuba.equip.PacketReceiver;


/**
 *
 * @author martinhudec
 */
public class RouterManager {

    List<PacketReceiver> availiablePorts;
    List<PacketReceiver> receiverList = null;
    PacketForwarder packetForwarder = null;
    Queue<Packet> packetBuffer;
    

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(RouterManager.class);

    public RouterManager() {
        availiablePorts = new ArrayList<>();
        receiverList = new ArrayList<>();
        packetBuffer = new ConcurrentLinkedQueue<>();
        
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
            
            availiablePorts.add(new PacketReceiver(port, packetBuffer, "fastEthernet 0/" + portNum));
        }
    }

   

    public void start() {
        System.out.println("Router manager start");
        logger.debug(availiablePorts.size() + " Router Manager start");
        if (!availiablePorts.isEmpty()) {
            for (PacketReceiver port : availiablePorts) {
                port.startThread();
            }
            packetForwarder = new PacketForwarder(packetBuffer, availiablePorts);
            new Thread(packetForwarder).start();
            System.out.println("zapol som RouterManager");
        }
    }

    public List<PacketReceiver> getAvailiablePorts() {
        return availiablePorts;
    }
    
    
}
