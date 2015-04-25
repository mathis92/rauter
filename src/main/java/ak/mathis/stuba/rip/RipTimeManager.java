/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ak.mathis.stuba.rip;

import java.util.ArrayList;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.equip.PacketGenerator;
import sk.mathis.stuba.equip.Port;
import sk.mathis.stuba.headers.IpV4Address;
import sk.mathis.stuba.router.RouterManager;
import sk.mathis.stuba.routingTable.RipStateEnum;
import sk.mathis.stuba.routingTable.RouteTypeEnum;
import sk.mathis.stuba.routingTable.RoutingTableItem;

/**
 *
 * @author martinhudec
 */
public class RipTimeManager implements Runnable {

    RouterManager manager;
    RipManager ripManager;
    Date updateTimer = null;
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(RipTimeManager.class);

    public RipTimeManager(RouterManager manager, RipManager ripManager) {
        this.manager = manager;
        this.ripManager = ripManager;
    }

    @Override
    public void run() {

        logger.info("[RipResponseManager] Thread start");
        //updateTimer = null;
        while (true) {
            if (updateTimer == null || ((new Date().getTime() - updateTimer.getTime()) > 30000)) {
                logger.info("[RipResponseManager] " + updateTimer);

                ArrayList<RoutingTableItem> ripPayload = new ArrayList<>();
                for (RoutingTableItem rtItem : manager.getRoutingTable().getRouteList()) {
                    for (RipTableItem rti : ripManager.getRipTable().getRipNetworkList()) {
                        if (IpV4Address.equals(rtItem.getDestinationNetwork(), rti.getNetworkAddress())) {
                            if (rtItem.getType() == RouteTypeEnum.directlyConnectedRoute) {
                                logger.info("[RipResponseManager] adding DIRECT route to payload " + rtItem.getDestinationNetwork());
                                ripPayload.add(rtItem);
                            }
                        }
                    }
                    if (rtItem.getType() == RouteTypeEnum.ripRoute) {
                        boolean added = false;
                        for (RipTableItem rti : ripManager.getRipTable().getRipNetworkList()) {
                            if (IpV4Address.equals(rtItem.getDestinationNetwork(), rti.getNetworkAddress())) {
                                added = true;
                                break;
                            }
                        }
                        if (!added) {
                            ripPayload.add(rtItem);
                            logger.info("[RipResponseManager] adding RIP route to payload " + rtItem.getDestinationNetwork());
                        }
                    }
                }
                for (Port port : manager.getAvailiablePorts()) {
                    for (RipTableItem rti : ripManager.getRipTable().getRipNetworkList()) {
                        if (port.getIpAddressByte() != null) {
                            if (rti.fitToNetwork(port.getIpAddress())) {
                                logger.info("[RipResponseManager] sending RIP response on port " + port.getPortName() + " ip address " + port.getIpAddress() + " mac address " + port.getMacAddress());
                                byte[] ripResponse = PacketGenerator.ripResponse(port, ripPayload);
                                port.getPcap().sendPacket(ripResponse);
                                break;
                            }
                        }
                    }
                }
                updateTimer = new Date();

            }

            for (RoutingTableItem routeTableItem : manager.getRoutingTable().getRouteList()) {
                if (routeTableItem.getType() == RouteTypeEnum.ripRoute) {
                    logger.info("[STATE TIMER] " + routeTableItem.getDestinationNetwork() + " " + routeTableItem.getUpdateTimer() + " " + routeTableItem.getInvalidTimer() + " " + routeTableItem.getHoldDownTimer() + " " + routeTableItem.getFlushTimer());
                    if (routeTableItem.getInvalidTimer() >= 180000 && routeTableItem.getRipState() != RipStateEnum.HOLDDOWN) {
                        logger.info("[INVALID] for " + routeTableItem.getDestinationNetwork());
                        routeTableItem.setState(RipStateEnum.INVALID);
                    }
                    if (routeTableItem.getHoldDownTimer() >= 180000) {
                        logger.info("[HOLDDOWN] for " + routeTableItem.getDestinationNetwork());
                        routeTableItem.setState(RipStateEnum.HOLDDOWN);
                    }
                    if (routeTableItem.getFlushTimer() >= 240000) {
                        logger.info("[FLUSH] for " + routeTableItem.getDestinationNetwork());
                        routeTableItem.setState(RipStateEnum.FLUSH);
                        manager.getRoutingTable().getRouteList().remove(routeTableItem);
                    }
                }
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                Logger.getLogger(RipTimeManager.class.getName()).log(Level.SEVERE, null, ex);
            }

        }
    }
}
