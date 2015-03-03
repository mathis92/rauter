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

/**
 *
 * @author Mathis
 */
public class PacketReceiver implements Runnable {

    private final StringBuilder errbuf = new StringBuilder();
    private final Queue<Packet> buffer;
    private Pcap pcap;
    private Packet pckt;
    private Boolean run = true;
    private static final Logger logger = LoggerFactory.getLogger(PacketReceiver.class);

    private String portName;
    private PcapIf port;
    private String ip = "192.168.56.200";
    private byte[] ipAddress = DataTypeHelper.ipAddressToByte(ip);
    private byte[] macAddress;
    private byte[] subnetMask;
    private PacketReceiver packetReceiver = this;

    public PacketReceiver(PcapIf port, Queue<Packet> buffer, String portName) {
        this.port = port;
        this.buffer = buffer;
        this.pcap = null;
        
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
        int timeout = 10 * 1000;           // 10 seconds in millis  
        pcap = Pcap.openLive(port.getName(), snaplen, flags, timeout, errbuf);
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String user) {

                if (packet != null) {
                    //logger.debug("PacketReceiver Start");
                    pckt = new Packet(packet, packetReceiver, pcap);
                    buffer.add(pckt);
                }
            }

        };

        while (run) {
            pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");
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

    public void setIpAddress(byte[] ipAddress) {
        this.ipAddress = ipAddress;
    }

    public void setSubnetMask(byte[] subnetMask) {
        this.subnetMask = subnetMask;
    }

}
