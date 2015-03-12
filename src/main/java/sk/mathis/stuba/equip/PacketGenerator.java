/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Array;
import org.jnetpcap.packet.PcapPacket;

/**
 *
 * @author martinhudec
 */
public class PacketGenerator {

    public static byte[] arpReply(byte[] sourceIP, byte[] destinationIP, byte[] sourceMAC, byte[] destinationMAC) {
     //   System.out.println("GENERUJEM ARP REPLY");
        System.out.println(DataTypeHelper.macAdressConvertor(sourceMAC));
        System.out.println(DataTypeHelper.macAdressConvertor(destinationMAC));
        System.out.println(DataTypeHelper.ipAdressConvertor(sourceIP));
        System.out.println(DataTypeHelper.ipAdressConvertor(destinationIP));
        byte[] arp = new byte[10];
        ByteArrayOutputStream arpReply = new ByteArrayOutputStream(42);
        arpReply.write(destinationMAC, 0, 6);
        arpReply.write(sourceMAC, 0, 6);

        arp[0] = 8;
        arp[1] = 6;
        arp[2] = 0;
        arp[3] = 1;
        arp[4] = 8;
        arp[5] = 0;
        arp[6] = 6;
        arp[7] = 4;
        arp[8] = 0;
        arp[9] = 2;
        arpReply.write(arp, 0, 10);
        arpReply.write(sourceMAC, 0, 6);
        arpReply.write(sourceIP, 0, 4);
        arpReply.write(destinationMAC, 0, 6);
        arpReply.write(destinationIP, 0, 4);

        return arpReply.toByteArray();
    }

    public static byte[] arpRequest(byte[] sourceIP, byte[] destinationIP, byte[] sourceMAC, byte[] destinationMAC) {
     //   System.out.println("GENERUJEM ARP REQUEST");
        System.out.println(DataTypeHelper.macAdressConvertor(sourceMAC));
        System.out.println(DataTypeHelper.macAdressConvertor(destinationMAC));
        System.out.println(DataTypeHelper.ipAdressConvertor(sourceIP));
        System.out.println(DataTypeHelper.ipAdressConvertor(destinationIP));
        byte[] arp = new byte[10];
        ByteArrayOutputStream arpReply = new ByteArrayOutputStream(42);
        arpReply.write(destinationMAC, 0, 6);
        arpReply.write(sourceMAC, 0, 6);

        arp[0] = 8;
        arp[1] = 6;
        arp[2] = 0;
        arp[3] = 1;
        arp[4] = 8;
        arp[5] = 0;
        arp[6] = 6;
        arp[7] = 4;
        arp[8] = 0;
        arp[9] = 1;
        arpReply.write(arp, 0, 10);
        arpReply.write(sourceMAC, 0, 6);
        arpReply.write(sourceIP, 0, 4);
        arpReply.write(destinationMAC, 0, 6);
        arpReply.write(destinationIP, 0, 4);

        return arpReply.toByteArray();
    }

    public static Packet icmpReply(Packet packet, byte[] sourceIP, byte[] destinationIP, byte[] sourceMAC, byte[] destinationMAC) {
        // Packet icmpReply = null;
    //    System.out.println("GENERUJEM ICMP REPLY");

        PcapPacket icmpReply = packet.getPacket();
        icmpReply.setByteArray(0, destinationMAC);
        icmpReply.setByteArray(6, sourceMAC);
        icmpReply.setByteArray(24, new byte[]{(byte) 0x00, (byte) 0x00});
        icmpReply.setByteArray(26, sourceIP);
        icmpReply.setByteArray(30, destinationIP);
        byte[] icmp = icmpReply.getByteArray(34, icmpReply.size() - 34);
        icmp[0] = 0x00;
        icmp[1] = 0x00;
        icmp[2] = 0x00;
        icmp[3] = 0x00;
        byte[] icmpCheckSum = DataTypeHelper.getUnsignedShort((int) DataTypeHelper.RFC1071Checksum(icmp, icmpReply.size() - 34));
        icmp[2] = icmpCheckSum[0];
        icmp[3] = icmpCheckSum[1];
        icmpReply.setByteArray(34, icmp);
        byte[] ipv4Header = icmpReply.getByteArray(14, 20);
        byte[] ipv4CheckSum = DataTypeHelper.getUnsignedShort((int) DataTypeHelper.RFC1071Checksum(ipv4Header, 20));
        icmpReply.setByteArray(24, ipv4CheckSum);

        packet.setPcapPacket(icmpReply);

        return packet;
    }
    
    public static Packet forwardPacket(Packet packet,byte[] sourceMac, byte[] destinationMac){
        PcapPacket newPcapPacket = packet.getPacket();
        
        newPcapPacket.setByteArray(0, destinationMac);
        newPcapPacket.setByteArray(6, sourceMac);
        packet.setPcapPacket(newPcapPacket);
        return packet;
    }
    /*
public static ripResponse(Packet packet, byte[]){
    
}    
    */
}
