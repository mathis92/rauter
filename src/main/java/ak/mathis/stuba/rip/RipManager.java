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
import sk.mathis.stuba.analysers.RipItem;
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.Packet;
import sk.mathis.stuba.equip.PacketGenerator;
import sk.mathis.stuba.equip.PacketReceiver;
import sk.mathis.stuba.router.RouterManager;
import sk.mathis.stuba.routingTable.RouteTypeEnum;
import sk.mathis.stuba.routingTable.RoutingTableItem;

/**
 *
 * @author martinhudec
 */
public class RipManager implements Runnable {

    RouterManager manager;
    Date updateTimer = null;

    public RipManager(RouterManager manager) {
        this.manager = manager;

    }

    @Override
    public void run() {
        while (true) {
            while (!manager.getRipPacketBuffer().isEmpty()) {
                Packet pckt = manager.getRipPacketBuffer().poll();
                if (Arrays.equals(pckt.getPort().getMacAddressByte(), pckt.getFrame().getSrcMacAddress())) {
                    break;
                }
                switch (DataTypeHelper.singleToInt(pckt.getFrame().getIpv4parser().getUdpParser().getRipParser().getCommand()[0])) {
                    case 2: {
                        for (RipItem ripItem : pckt.getFrame().getIpv4parser().getUdpParser().getRipParser().getRipItemsList()) {
                            byte[] nextHop = ripItem.getNextHop();
                            if (Arrays.equals(ripItem.getNextHop(), DataTypeHelper.ipAddressToByteFromString("0.0.0.0"))) {
                                nextHop = pckt.getFrame().getIpv4parser().getSourceIPbyte();
                            }
                            manager.getRoutingTable().addRipRoute(ripItem.getIpv4Address(), ripItem.getSubnetMask(), nextHop, DataTypeHelper.toInt(ripItem.getMetric()));
                        }
                        manager.getRoutingTable().orderRoutingTable();
                        break;
                    }
                }
            }
            if (updateTimer == null || ((new Date().getTime() - updateTimer.getTime()) > 30000)) {
                ArrayList<RoutingTableItem> ripPay = new ArrayList<>();
                for (RoutingTableItem rtItem : manager.getRoutingTable().getRouteList()) {
                    if (rtItem.getType() == RouteTypeEnum.ripRoute) {
                        ripPay.add(rtItem);
                    }
                }
                for (PacketReceiver port : manager.getAvailiablePorts()) {
                    if (port.getIpAddressByte() != null) {
                        byte[] ripResponse = PacketGenerator.ripResponse(port, ripPay);
                        port.getPcap().sendPacket(ripResponse);
                    }
                }
                updateTimer = new Date();
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException ex) {
                Logger.getLogger(RipManager.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
}
