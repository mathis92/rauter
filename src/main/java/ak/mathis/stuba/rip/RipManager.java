/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ak.mathis.stuba.rip;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.packet.PcapPacket;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.analysers.RipItem;
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.Packet;
import sk.mathis.stuba.equip.PacketGenerator;
import sk.mathis.stuba.equip.Port;
import sk.mathis.stuba.headers.IpV4Address;
import sk.mathis.stuba.router.RouterManager;
import sk.mathis.stuba.routingTable.RouteTypeEnum;
import sk.mathis.stuba.routingTable.RoutingTableItem;

/**
 *
 * @author martinhudec
 */
public class RipManager implements Runnable {

    RouterManager manager;
    RipTable ripTable;
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(RipManager.class);

    public RipManager(RouterManager manager) {
        this.manager = manager;
        ripTable = new RipTable();
        new Thread(ripTable).start();
        new Thread(new RipTimeManager(manager, this)).start();
    }

    @Override
    public void run() {
        logger.info("[RipManager] Thread start");
        while (true) {
            while (!manager.getRipPacketBuffer().isEmpty()) {
                Packet pckt = manager.getRipPacketBuffer().poll();
                if (ripTable.getRipNetworkList().isEmpty()) {
                    logger.info("[RIP not configured]");
                }
                for (RipTableItem rti : ripTable.getRipNetworkList()) {
                    if (pckt.fitToNetwork(rti.getNetworkAddress(), rti.getNetMaskAddress())) {
                        logger.info("[RIP FITS TO RIP NETWORKS] " + pckt.getSourceIp());
                        switch (DataTypeHelper.singleToInt(pckt.getFrame().getIpv4parser().getUdpParser().getRipParser().getCommand()[0])) {
                            case 2: {
                                for (RipItem ripItem : pckt.getFrame().getIpv4parser().getUdpParser().getRipParser().getRipItemsList()) {
                                    byte[] nextHop = ripItem.getNextHop();
                                    if (Arrays.equals(ripItem.getNextHop(), DataTypeHelper.ipAddressToByteFromString("0.0.0.0"))) {
                                        nextHop = pckt.getFrame().getIpv4parser().getSourceIPbyte();
                                    }
                                    manager.getRoutingTable().addRipRouteToTable(ripItem.getIpv4Address(), ripItem.getSubnetMask(), nextHop, DataTypeHelper.toInt(ripItem.getMetric()));
                                }
                                manager.getRoutingTable().orderRoutingTable();
                                break;
                            }
                        }
                    } else {
                        logger.info("[RIP DOES NOT FIT TO RIP NETWORKS] " + pckt.getSourceIp());
                    }
                }
            }

            try {
                Thread.sleep(1);
            } catch (InterruptedException ex) {
                Logger.getLogger(RipManager.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void addRipNetwork(String ip, String netMask) {
        ripTable.addRipNetwork(new IpV4Address(ip), new IpV4Address(netMask));
        logger.info("[ACTUAL RIP NETWORKS]:");
        for (RipTableItem ripNetwork : ripTable.getRipNetworkList()) {
            logger.info("[RIP network] " + ripNetwork.toString());
        }
    }

    public void sendRipResponses() {

    }

    public RipTable getRipTable() {
        return ripTable;
    }

}
