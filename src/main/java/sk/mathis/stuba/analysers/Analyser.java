/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.analysers;

import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.equip.DataTypeHelper;

public class Analyser {

    private Frame frame;

    public Frame analyzePacket(PcapPacket packet) {

        frame = new Frame(packet);

        if (frame.getIsIpv4()) {

            if (frame.getIpv4parser().getTcpParser() != null) {

                if (frame.getIpv4parser().getTcpParser().getIsTcp()) {
                    frame.setProtocol("TCP");

                    String tcpPort = DataTypeHelper.tcpMap.get(frame.getIpv4parser().getTcpParser().getDestinationPort());
                    if (tcpPort == null) {
                        tcpPort = DataTypeHelper.tcpMap.get(frame.getIpv4parser().getTcpParser().getSourcePort());

                    }
                    if (tcpPort != null) {
                        if (tcpPort.equals("www")) {
                            tcpPort = "http";
                        }

                        frame.setApplicationProtocol(tcpPort);
                    }
                }
            }
            if (frame.getIpv4parser().getUdpParser() != null) {
                if (frame.getIpv4parser().isIsUdp()) {
                    frame.setProtocol("UDP");
                    String udpPort = DataTypeHelper.udpMap.get(DataTypeHelper.toInt(frame.getIpv4parser().getUdpParser().getDestinationPort()));
                    if (udpPort == null) {
                        udpPort = DataTypeHelper.udpMap.get(DataTypeHelper.toInt(frame.getIpv4parser().getUdpParser().getSourcePort()));
                    }

                    if (udpPort != null) {
                        if (udpPort.equals("www")) {
                            udpPort = "http";
                        }
                        frame.setApplicationProtocol(udpPort);
                    }
                }
            }

        }
        return frame;
    }

    public Frame getFrame() {
        return frame;
    }
}
