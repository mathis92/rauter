/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.headers;

import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.equip.Packet;
import sk.mathis.stuba.equip.PacketReceiver;

/**
 *
 * @author martinhudec
 */
public class ArpPacket {

    byte[] sourceIp; 
    byte[] destinationIP;
    byte[] sourceMAC; 
    byte[] destinationMAC; 
    byte[] arpSourceIP; 
    byte[] arpDestinationIP; 
    PacketReceiver receivedPort; 
    
    
    public ArpPacket(Packet packet) {
    }
    
}
