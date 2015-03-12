/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.analysers;

import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.equip.DataTypeHelper;

/**
 *
 * @author Mathis
 */
public class UdpParser implements IAnalyser {

    private byte[] sourcePort;
    private byte[] destinationPort;
    private boolean isRip = false;
    private PcapPacket packet;
    private Integer ihlSet;
    private RipParser ripParser;
    public UdpParser(PcapPacket packet, Integer ihlSet) {
        this.ihlSet = ihlSet;
        this.packet = packet;
        analyse();
    }

    //  public TcpParser() {
    //  }
    @Override
    public void analyse() {
        sourcePort = packet.getByteArray(34 + ihlSet, 2);
        destinationPort = packet.getByteArray(36 + ihlSet, 2);
        if(DataTypeHelper.toInt(destinationPort) == 520){
            isRip = true;
            ripParser = new RipParser(packet, ihlSet);
        }
    }

    public byte[] getDestinationPort() {
        return destinationPort;
    }

    public boolean isIsRip() {
        return isRip;
    }


    public RipParser getRipParser() {
        return ripParser;
    }

    public byte[] getSourcePort() {
        return sourcePort;
    }

}
