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
public class ArpParser implements IAnalyser {

    private String operationType;
    private  byte[] sourceIPbyte;
    private  byte[] destinationIPbyte;
    private  byte[] destinationMACbyte;
    private  byte[] sourceMACbyte;
    private final PcapPacket packet;
    
    public ArpParser(PcapPacket packet) {
        this.packet = packet;
        this.analyse();
    }

    @Override
    public void analyse() {
        byte[] opType = packet.getByteArray(20, 2);
        if (DataTypeHelper.toInt(opType) == 1) {
            operationType = "ARP-Request";
        } else if (DataTypeHelper.toInt(opType) == 2) {
            operationType = "ARP-Reply";
        }
            sourceMACbyte = packet.getByteArray(22, 6);
            sourceIPbyte = packet.getByteArray(28, 4);
            destinationMACbyte = packet.getByteArray(32, 6);
            destinationIPbyte = packet.getByteArray(38, 4);
    }

    public byte[] getDestinationIPbyte() {
        return destinationIPbyte;
    }

    public byte[] getDestinationMACbyte() {
        return destinationMACbyte;
    }

    public String getOperationType() {
        return operationType;
    }

    public byte[] getSourceIPbyte() {
        return sourceIPbyte;
    }

    public byte[] getSourceMACbyte() {
        return sourceMACbyte;
    }

    
    
    
}
