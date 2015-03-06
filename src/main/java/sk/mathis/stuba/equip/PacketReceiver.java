/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import java.io.IOException;
import java.util.Arrays;
import java.util.Queue;
import java.util.logging.Level;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.arp.ArpTable;

/**
 *
 * @author Mathis
 */
public class PacketReceiver implements Runnable {

    private final StringBuilder errbuf = new StringBuilder();
    private final Queue<Packet> buffer;
    private final Queue<Packet> arpBuffer;
    private ArpTable arpTable;
    private Pcap pcap;
    private Packet pckt;
    private Boolean run = true;
    private static final Logger logger = LoggerFactory.getLogger(PacketReceiver.class);

    private String portName;
    private PcapIf port;
    
    private byte[] ipAddress = null;
    private byte[] macAddress;
    private byte[] subnetMask;
    private PacketReceiver packetReceiver = this;

    public PacketReceiver(PcapIf port, Queue<Packet> buffer, Queue<Packet> arpBuffer, String portName, ArpTable arpTable) {
        this.port = port;
        this.buffer = buffer;
        this.pcap = null;
        this.arpBuffer = arpBuffer;
        this.arpTable = arpTable;

        try {
            macAddress = port.getHardwareAddress();
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(PacketReceiver.class.getName()).log(Level.SEVERE, null, ex);
        }

        this.portName = portName;

    }

    @Override
    public void run() {

        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 1;           // 10 seconds in millis  
        pcap = Pcap.openLive(port.getName(), snaplen, flags, timeout, errbuf);
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String user) {

                if (packet != null) {
                    //logger.debug("PacketReceiver Start");

                    pckt = new Packet(packet, packetReceiver, pcap);
                    if (pckt.getFrame().getIsArp()) {
                        System.out.println(packet.getByte(12) + " - " + packet.getByte(13) + " - " + packet.getByte(21));
                        //    logger.info("arp destination ip" + DataTypeHelper.ipAdressConvertor(pckt.getFrame().getArpParser().getDestinationIPbyte()) + " arp source  ip" + DataTypeHelper.ipAdressConvertor(pckt.getFrame().getArpParser().getSourceIPbyte()) + " " + pckt.getFrame().getArpParser().getOperationType());
                        if (Arrays.equals(pckt.getPort().getIpAddress(), pckt.getFrame().getArpParser().getDestinationIPbyte())) {
                            arpBuffer.add(pckt);
                        }
                    } else {

                        buffer.add(pckt);
                    }
                }
            }

        };

        while (run) {
            //   System.out.println("Papam Pakat");
            pcap.dispatch(1, jpacketHandler, null);
        }
    }

    public void stop() {
        this.run = false;
    }

    public void startThread() {
        this.run = true;
        System.out.println("zapinam thread na " + port.getName());
        new Thread(this).start();
    }

    public void setPcap(Pcap pcap) {
        this.pcap = pcap;
    }

    public Pcap getPcap() {
        return pcap;
    }

    public PcapIf getPcapIfPort() {
        return port;
    }

    public String getPortName() {
        return portName;
    }

    public byte[] getIpAddress() {
        return ipAddress;
    }

    public PcapIf getPort() {
        return port;
    }

    public byte[] getSubnetMask() {
        return subnetMask;
    }

    public byte[] getMacAddress() {
        return macAddress;
    }

    public void setPortDetails(byte[] ipAddress, byte[] subnetMask) {
        this.ipAddress = ipAddress;
        this.subnetMask = subnetMask;

    }
    
    

    @Override
    public String toString() {
        return this.getPortName(); //To change body of generated methods, choose Tools | Templates.
    }

}
