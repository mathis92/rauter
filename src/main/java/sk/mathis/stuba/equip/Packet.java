/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;

/**
 *
 * @author Mathis
 */
public class Packet {

    PcapPacket packet;
    PacketReceiver port;
    Pcap pcap;

    public Packet(PcapPacket packet, PacketReceiver port, Pcap pcap) {
        this.packet = packet;
        this.port = port;
        this.pcap = pcap;
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

}
