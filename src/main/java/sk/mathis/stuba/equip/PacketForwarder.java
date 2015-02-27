/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.analysers.Analyser;
import sk.mathis.stuba.analysers.Frame;

/**
 *
 * @author Mathis
 */
public class PacketForwarder implements Runnable {

    private Queue<Packet> buffer;
    private PacketSender sender;
    private Analyser analyser;
    private List<PacketReceiver> receiverList;
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(PacketForwarder.class);

    public PacketForwarder(Queue<Packet> buffer, List<Port> portList, List<PacketReceiver> receiverList) {
        this.buffer = buffer;
        this.receiverList = receiverList;
        this.sender = new PacketSender(portList, receiverList);
        this.analyser = new Analyser();
    }

    @Override
    public void run() {
        System.out.println("Zapol som packet Forwarder");
        while (true) {
            while (!buffer.isEmpty()) {
                Packet pckt = buffer.poll();
                Frame frame = analyser.analyzePacket(pckt.getPacket());
                // System.out.println(pckt.getPort().getPortName() + " " + frame.getFrameType());
                if (frame.getIsArp()) {
                    logger.info("arp destination ip" + DataTypeHelper.ipAdressConvertor(frame.getArpParser().getDestinationIPbyte()) + " arp source  ip" + DataTypeHelper.ipAdressConvertor(frame.getArpParser().getSourceIPbyte()));
                    if (Arrays.equals(pckt.getPort().getIpAddress(), frame.getArpParser().getDestinationIPbyte())) {
                        if (frame.getArpParser().getOperationType().equalsIgnoreCase("arp-request")) {
                            logger.info("dostal som request arp pre mna ");
                            
                            byte[] arpReply = PacketGenerator.arpReply(pckt.getPort().getIpAddress(), frame.getArpParser().getSourceIPbyte(), pckt.getPort().getMacAddress(), frame.getArpParser().getSourceMACbyte());
                            for (int i = 0; i < 42; i++) {
                                System.out.print(arpReply[i] + " ");
                            }
                            
                            sender.sendPacket(arpReply,pckt.getPort());
                        }
                    }
                }
                
                if (frame.getIsIpv4()) {
                if(frame.getIpv4parser().getIsIcmp()){
                    
                }
                    // logger.info("source ip " +DataTypeHelper.ipAdressConvertor(frame.getIpv4parser().getSourceIPbyte()) +" "+ DataTypeHelper.ipAdressConvertor(frame.getIpv4parser().getDestinationIPbyte()));
                }
               //logger.info(pckt.getPort().getPortName() + " " + pckt.getPacket().getCaptureHeader());

                //sender.sendPacket(pckt);
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException ex) {
                Logger.getLogger(PacketForwarder.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

}
