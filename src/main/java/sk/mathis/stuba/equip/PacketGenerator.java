/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Array;

/**
 *
 * @author martinhudec
 */
public class PacketGenerator {

    public static byte[] arpReply(byte[] sourceIP, byte[] destinationIP, byte[] sourceMAC, byte[] destinationMAC) {
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

   /* public static Packet icmpReply(Packet packet, byte[] sourceIP, byte[] destinationIP, byte[] sourceMAC, byte[] destinationMAC) {
        Packet icmpReply = null;
        packet.getPacket().setByteArray(0, destinationMAC);
        packet.getPacket().setByteArray(6, sourceMAC);
        packet.getPacket().setByteArray(22, CHECKSUM);
        packet.getPacket().setByteArray(26, sourceIP);
        packet.getPacket().setByteArray(30, destinationIP);
        byte[] typeCodeCheckSum = new byte[4];
        typeCodeCheckSum[0] = 0;
        typeCodeCheckSum[1] = 0;
        typeCodeCheckSum[2] = 0;
        typeCodeCheckSum[3] = 0;
        packet.getPacket().setByteArray(36, typeCodeCheckSum);
        
        return icmpReply;
    }*/
}
