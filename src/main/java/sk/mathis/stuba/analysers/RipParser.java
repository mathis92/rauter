/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.analysers;

import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.equip.DataTypeHelper;

/**
 *
 * @author martinhudec
 */
public class RipParser implements IAnalyser {

    PcapPacket pckt;
    Integer ihlSet;
    byte[] command;
    byte[] version;
    List<RipItem> ripItemsList = new ArrayList<>();

    public RipParser(PcapPacket pckt, Integer ihlSet) {
        this.pckt = pckt;
        this.ihlSet = ihlSet;
        analyse();
    }

    @Override
    public void analyse() {
        System.out.println(ihlSet);
        command = pckt.getByteArray(42 + ihlSet, 1);
        version = pckt.getByteArray(43 + ihlSet, 1);
        //System.out.println("command " + DataTypeHelper.singleToInt(command[0]) + " version " + DataTypeHelper.singleToInt(version[0]));

        //System.out.println(pckt.getCaptureHeader().caplen());

        for (int i = 46+ihlSet; i < pckt.getCaptureHeader().caplen(); i = i + 20) {
           // System.out.println(i);
            RipItem ripRoute = new RipItem(pckt.getByteArray(i, 2), pckt.getByteArray(i+2, 2), pckt.getByteArray(i+4, 4), pckt.getByteArray(i+8, 4), pckt.getByteArray(i+12, 4), pckt.getByteArray(i+16, 4));
            ripItemsList.add(ripRoute);
        }
    }

    public List<RipItem> getRipItemsList() {
        return ripItemsList;
    }

    public byte[] getCommand() {
        return command;
    }

    public byte[] getVersion() {
        return version;
    }

}
