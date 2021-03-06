/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import java.util.Arrays;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.analysers.Analyser;
import sk.mathis.stuba.analysers.Frame;
import sk.mathis.stuba.headers.IpV4Address;
import sk.mathis.stuba.headers.MacAddress;
import sk.mathis.stuba.routingTable.RoutingTable;

/**
 *
 * @author Mathis
 */
public class Packet {

    PcapPacket packet;
    Port port;
    Pcap pcap;
    Frame frame;
    Analyser analyzer = new Analyser();
    IpV4Address sourceIp;
    IpV4Address destinationIP;
    MacAddress sourceMAC;
    MacAddress destinationMAC;
    IpV4Address arpSourceIP;
    IpV4Address arpDestinationIP;
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(Packet.class);

    public Packet(PcapPacket packet, Port port, Pcap pcap) {
        this.packet = packet;
        this.port = port;
        this.pcap = pcap;
        frame = analyzer.analyzePacket(packet);
        if (frame.getIsIpv4()) {
            sourceIp = new IpV4Address(frame.getIpv4parser().getSourceIP());
        }
    }

    public Port getPort() {
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

    public boolean fitToNetwork(IpV4Address network, IpV4Address netMask) {
        boolean fit = IpV4Address.equals(network,
                port.getIpAddress().checkRange(netMask));
        logger.info("[FIT to network check] " + " src IP: " + port.getIpAddress() + " network:  " + network + " -> " + netMask + " RESULT: " + fit);
        return fit;
    }

    public IpV4Address getArpSourceIP() {
        return new IpV4Address(frame.getArpParser().getSourceIPbyte());
    }

    public IpV4Address getSourceIp() {
        return new IpV4Address(frame.getIpv4parser().getSourceIPbyte());
    }

    public IpV4Address getDestinationIP() {
        return new IpV4Address(frame.getIpv4parser().getDestinationIPbyte());
    }

    public MacAddress getSrcMac() {
        return new MacAddress(frame.getSrcMacAddress());
    }

    public MacAddress getDstMac() {
        return new MacAddress(frame.getDstMacAddress());
    }

    public IpV4Address getPortIp() {
        return new IpV4Address(port.getIpAddressByte());
    }

    public MacAddress getPortMac() {
        return new MacAddress(port.getMacAddressByte());
    }

    public boolean isArpRequest() {
        if (frame.getArpParser().getOperationType().equals("arp-request")) {
            return true;
        } else {
            return false;
        }
    }
}
