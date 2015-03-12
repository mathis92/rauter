/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ak.mathis.stuba.rip;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import sk.mathis.stuba.analysers.RipItem;
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.Packet;
import sk.mathis.stuba.router.RouterManager;
import sk.mathis.stuba.routingTable.RoutingTableItem;

/**
 *
 * @author martinhudec
 */
public class RipManager implements Runnable {

    RouterManager manager;

    public RipManager(RouterManager manager) {
        this.manager = manager;

    }

    @Override
    public void run() {
        while (true) {
            while (!manager.getRipPacketBuffer().isEmpty()) {
                Packet pckt = manager.getRipPacketBuffer().poll();
                switch (DataTypeHelper.singleToInt(pckt.getFrame().getIpv4parser().getUdpParser().getRipParser().getCommand()[0])) {
                    case 2: {
                        for (RipItem ripItem : pckt.getFrame().getIpv4parser().getUdpParser().getRipParser().getRipItemsList()) {
                            byte[] nextHop = ripItem.getNextHop();
                            if (Arrays.equals(ripItem.getNextHop(), DataTypeHelper.ipAddressToByteFromString("0.0.0.0"))) {
                                nextHop = pckt.getFrame().getIpv4parser().getSourceIPbyte();
                            }
                            manager.getRoutingTable().addRipRoute(ripItem.getIpv4Address(), ripItem.getSubnetMask(), nextHop, pckt.getPort(), DataTypeHelper.toInt(ripItem.getMetric()));
                        }
                        break;
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
}
