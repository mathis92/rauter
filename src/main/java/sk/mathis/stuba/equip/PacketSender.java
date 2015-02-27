/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

/**
 *
 * @author Mathis
 */
public class PacketSender {

    byte[] packetByteArray;
    List<Port> portList;
    List<PacketReceiver> receivedList;
    private Integer sent = 0;

    public PacketSender(List<Port> portList, List<PacketReceiver> receivedList) {
        this.portList = portList;
        this.receivedList = receivedList;
    }

    
    
    public void sendPacket(Packet packet) {
        sent = 0;
        // System.out.println(packet.getPacket().getCaptureHeader().caplen());
        this.packetByteArray = packet.getPacket().getByteArray(0, packet.getPacket().getCaptureHeader().caplen());

        for (PacketReceiver packetReceiver : receivedList) {

            if (packetReceiver.getPcap().sendPacket(packetByteArray) != Pcap.OK) {
                System.err.println(packet.getPcap().getErr());
            }

        }

        if (sent.equals(0)) {
            for (PacketReceiver packetReceiver : receivedList) {
                if (packetReceiver.getPcap() != null) {
                    if (packetReceiver.getPcap().sendPacket(packetByteArray) != Pcap.OK) {
                        System.err.println(packetReceiver.getPcap().getErr());
                    }
                }
            }

        }
    }
     public void sendPacket(byte[] packet, Port port) {
        sent = 0;
        // System.out.println(packet.getPacket().getCaptureHeader().caplen());
        this.packetByteArray = packet;

        for (PacketReceiver packetReceiver : receivedList) {
            if(packetReceiver.getPort().getPortName().equals(port.getPortName())){
            if (packetReceiver.getPcap().sendPacket(packetByteArray) != Pcap.OK) {
                System.err.println("SE TO DO*EBAUO");
            }
            }

        }

        if (sent.equals(0)) {
            for (PacketReceiver packetReceiver : receivedList) {
                if (packetReceiver.getPcap() != null) {
                    if (packetReceiver.getPcap().sendPacket(packetByteArray) != Pcap.OK) {
                        System.err.println(packetReceiver.getPcap().getErr());
                    }
                }
            }

        }
    }
    
}
