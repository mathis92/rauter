/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Array;
import java.util.ArrayList;
import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.headers.IpV4Address;
import sk.mathis.stuba.headers.MacAddress;
import sk.mathis.stuba.routingTable.RoutingTableItem;

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
        Integer ttl = DataTypeHelper.singleToInt(icmpReply.getByte(22));

        icmpReply.setByteArray(22, DataTypeHelper.longToBytes(ttl - 1));
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

    public static Packet forwardPacket(Packet packet, byte[] sourceMac, byte[] destinationMac) {
        PcapPacket newPcapPacket = packet.getPacket();

        newPcapPacket.setByteArray(0, destinationMac);
        newPcapPacket.setByteArray(6, sourceMac);
        Integer ttl = DataTypeHelper.singleToInt(newPcapPacket.getByte(22));

        newPcapPacket.setByteArray(22, DataTypeHelper.longToBytes(ttl - 1));
        packet.setPcapPacket(newPcapPacket);
        return packet;
    }

    public static byte[] ripResponse(PacketReceiver port, ArrayList<RoutingTableItem> payload) {
        ByteArrayOutputStream ripResponse = new ByteArrayOutputStream(14 + 20 + 8 + 4 + (payload.size() * 20));
        ByteArrayOutputStream ethernet = new ByteArrayOutputStream(14);
        ByteArrayOutputStream ipv4 = new ByteArrayOutputStream(20);
        ByteArrayOutputStream udp = new ByteArrayOutputStream(8);
        ByteArrayOutputStream rip = new ByteArrayOutputStream(4 + payload.size() * 20);

        ethernet.write(new byte[]{0x01, 0x00, 0x5e, 0x00, 0x00, 0x09}, 0, 6);
        ethernet.write(port.getMacAddressByte(), 0, 6);
        ethernet.write(new byte[]{0x08, 0x00}, 0, 2);
        ipv4.write(new byte[]{0x45}, 0, 1);
        ipv4.write(new byte[]{(byte) 0xC0}, 0, 1);
        ipv4.write(DataTypeHelper.getUnsignedShort(20 + 4 + 8 + payload.size() * 20), 0, 2);
        ipv4.write(new byte[]{0x00, 0x00}, 0, 2);
        ipv4.write(new byte[]{0x00, 0x00}, 0, 2);
        ipv4.write(new byte[]{0x02}, 0, 1);
        ipv4.write(new byte[]{0x11}, 0, 1);
        ipv4.write(new byte[]{0x00, 0x00}, 0, 2);
        ipv4.write(port.getIpAddressByte(), 0, 4);
        ipv4.write(new IpV4Address("224.0.0.9").getBytes(), 0, 4);
        byte[] ipv4CheckSum = DataTypeHelper.getUnsignedShort((int) DataTypeHelper.RFC1071Checksum(ipv4.toByteArray(), 20));
        byte[] ipv4ByteArray = ipv4.toByteArray();
        ipv4ByteArray[10] = ipv4CheckSum[0];
        ipv4ByteArray[11] = ipv4CheckSum[1];
        udp.write(new byte[]{0x02, 0x08}, 0, 2);
        udp.write(new byte[]{0x02, 0x08}, 0, 2);
        udp.write(DataTypeHelper.getUnsignedShort(payload.size() * 20 + 4 + 8), 0, 2);
        udp.write(new byte[]{0x00, 0x00}, 0, 2);
        rip.write(new byte[]{0x02}, 0, 1);
        rip.write(new byte[]{0x02}, 0, 1);
        rip.write(new byte[]{0x00, 0x00}, 0, 2);
        for (RoutingTableItem rtItem : payload) {
            rip.write(new byte[]{0x00, 0x02}, 0, 2);
            rip.write(new byte[]{0x00, 0x00}, 0, 2);
            rip.write(rtItem.getDestinationNetworkBytes(), 0, 4);
            rip.write(rtItem.getNetMask(), 0, 4);
            rip.write(new IpV4Address("0.0.0.0").getBytes(), 0, 4);
            rip.write(DataTypeHelper.getByteArrayFromInte(4, rtItem.getMetric()), 0, 4);
        }
        ripResponse.write(ethernet.toByteArray(),0,14);
        ripResponse.write(ipv4ByteArray, 0, 20);
        ripResponse.write(udp.toByteArray(), 0 , 8);
        ripResponse.write(rip.toByteArray(),0,4 + payload.size()*20);
        
        return ripResponse.toByteArray();
    }

}
