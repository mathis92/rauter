/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.analysers.Analyser;
import sk.mathis.stuba.analysers.Frame;

/**
 *
 * @author Mathis
 */
public class Packet {

    PcapPacket packet;
    PacketReceiver port;
    Pcap pcap;
    Frame frame;
    Analyser analyzer = new Analyser();

    public Packet(PcapPacket packet, PacketReceiver port, Pcap pcap) {
        this.packet = packet;
        this.port = port;
        this.pcap = pcap;
        frame = analyzer.analyzePacket(packet);
    }

    public PacketReceiver getPort() {
        return port;
    }

    public PcapPacket getPacket() {
        return packet;
    }
    
    public Pcap getPcap() {
        return pcap;
    }

    public void setPcap(Pcap pcap) {
        this.pcap = pcap;
    }

    public void setPcapPacket(PcapPacket packet) {
        this.packet = packet;
        frame = analyzer.analyzePacket(packet);
    }

    public Frame getFrame() {
        return frame;
    }
    

}
