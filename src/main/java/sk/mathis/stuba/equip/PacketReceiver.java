/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import ak.mathis.stuba.rip.RipManager;
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
import sk.mathis.stuba.headers.IpV4Address;
import sk.mathis.stuba.headers.MacAddress;

/**
 *
 * @author Mathis
 */
public class PacketReceiver implements Runnable {

    private final StringBuilder errbuf = new StringBuilder();
    private final Queue<Packet> buffer;
    private final Queue<Packet> arpBuffer;
    private final Queue<Packet> ripBuffer;
    private ArpTable arpTable;
    private RipManager ripManager;

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

    public PacketReceiver(PcapIf port, Queue<Packet> buffer, Queue<Packet> arpBuffer, String portName, ArpTable arpTable, Queue<Packet> ripBuffer, RipManager ripManager) {
        this.port = port;
        this.buffer = buffer;
        this.pcap = null;
        this.arpBuffer = arpBuffer;
        this.arpTable = arpTable;
        this.ripBuffer = ripBuffer;
        this.ripManager = ripManager;

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
                    pckt = new Packet(packet, packetReceiver, pcap);
                    if (pckt.getFrame().getIsArp()) {
                        System.out.println("ARP PACKETLA");
                        arpBuffer.add(pckt);
                    } else if (pckt.getFrame().getIsIpv4() && pckt.getFrame().getIpv4parser().isIsUdp() && pckt.getFrame().getIpv4parser().getUdpParser().isIsRip()) {
                        System.out.println("RIP PACKETLA");

                        if (Arrays.equals(pckt.getFrame().getIpv4parser().getDestinationIPbyte(), DataTypeHelper.ipAddressToByteFromString("224.0.0.9"))) {
                            if (pckt.getFrame().getIpv4parser().isIsUdp()) {
                                if (pckt.getFrame().getIpv4parser().getUdpParser().isIsRip()) {
                                    ripBuffer.add(pckt);
                                }
                            }
                        }
                    } else {
                        if (pckt.getFrame().getIsIpv4()) {
                            if (pckt.getFrame().getIpv4parser().getIsIcmp()) {
                                System.out.println("ICMP PACKETLA");
                            }
                        }
                        buffer.add(pckt);
                    }
                }
            }

        };

        while (run) {
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

    public byte[] getIpAddressByte() {
        return ipAddress;
    }

    public PcapIf getPort() {
        return port;
    }

    public RipManager getRipManager() {
        return ripManager;
    }

    public Queue<Packet> getRipBuffer() {
        return ripBuffer;
    }

    public byte[] getSubnetMask() {
        return subnetMask;
    }

    public byte[] getMacAddressByte() {
        return macAddress;
    }

    public MacAddress getMacAddress(){
        return new MacAddress(macAddress);
    }
    public IpV4Address getIpAddress(){
        return new IpV4Address(ipAddress);
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
