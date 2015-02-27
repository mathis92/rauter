/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import java.util.Arrays;
import java.util.Queue;
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

    private final Port port;
    private final StringBuilder errbuf = new StringBuilder();
    private final Queue<Packet> buffer;
    private Pcap pcap;
    private Packet pckt;
    private Boolean run = true;
    private static final Logger logger = LoggerFactory.getLogger(PacketReceiver.class);

    public PacketReceiver(Port port, Queue<Packet> buffer) {
        this.port = port;
        this.buffer = buffer;
        this.pcap = null;

    }

    @Override
    public void run() {

        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        pcap = Pcap.openLive(port.getPcapIfPort().getName(), snaplen, flags, timeout, errbuf);
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String user) {

                if (packet != null) {
                    //logger.debug("PacketReceiver Start");
                    pckt = new Packet(packet, port, pcap);
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
        System.out.println("zapinam thread na " + port.getPcapIfPort().getName());
        new Thread(this).start();
    }

    public void setPcap(Pcap pcap) {
        this.pcap = pcap;
    }

    public Pcap getPcap() {
        return pcap;
    }

    public Port getPort() {
        return port;
    }

}
