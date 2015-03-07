/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.routingTable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.net.util.SubnetUtils;
import sk.mathis.stuba.arp.ArpTableItem;
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.Packet;
import sk.mathis.stuba.equip.PacketReceiver;
import sk.mathis.stuba.router.RouterManager;

/**
 *
 * @author martinhudec
 */
public class RoutingTable implements Runnable {

    List<RoutingTableItem> routeList;
    RouterManager manager;

    public RoutingTable(RouterManager manager) {
        this.routeList = new ArrayList<>();
        this.manager = manager;
        System.out.println("VYTVORENA ROUTING TABLE");
    }

    @Override
    public void run() {
        while (true) {
            fillDirectlyConnected();
            orderRoutingTable();

            try {
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                Logger.getLogger(RoutingTable.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void fillDirectlyConnected() {

        for (PacketReceiver port : manager.getAvailiablePorts()) {
            int added = 0;

            if (port.getIpAddress() != null) {
                for (RoutingTableItem route : manager.getRoutingTable().getRouteList()) {
                    if (port.getPortName().equals(route.getPort().getPortName())) {
                        added = 1;
                        route.updateRouteData(resolveNetwork(port.getIpAddress(), port.getSubnetMask()), port.getSubnetMask(), port.getIpAddress(), port, 1, "D");

                    }
                }
                if (added == 0) {
                    RoutingTableItem newDirectlyConnected = new RoutingTableItem(resolveNetwork(port.getIpAddress(), port.getSubnetMask()), port.getSubnetMask(), port.getIpAddress(), port, 1, "D");
                    routeList.add(newDirectlyConnected);
                }
            }
        }
    }

    public byte[] resolveNetwork(byte[] ipAddress, byte[] subnetMask) {
        byte[] network = new byte[4];
        for (int i = 0; i < 4; i++) {
            byte tmp = (byte) (ipAddress[i] & (byte) subnetMask[i]);
            network[i] = tmp;
        }
        return network;
    }

    public RoutingTableItem resolveRoute(Packet pckt) {
        for (RoutingTableItem route : manager.getRoutingTable().getRouteList()) {
            SubnetUtils utils = new SubnetUtils(route.getCidrRange());
            boolean isInRange = utils.getInfo().isInRange(DataTypeHelper.ipAdressConvertor(pckt.getFrame().getIpv4parser().getDestinationIPbyte()));
            if (isInRange) {
                return route;
            }
        }
        return null;
    }

    public List<RoutingTableItem> getRouteList() {
        return routeList;
    }

    public void orderRoutingTable() {

        Collections.sort(routeList, new Comparator<RoutingTableItem>() {

            @Override
            public int compare(RoutingTableItem o1, RoutingTableItem o2) {
                Integer ad = o1.getAdministrativeDistance().compareTo(o1.getAdministrativeDistance());
                //  System.out.println(o1.getAdministrativeDistance() + " " + o2.getAdministrativeDistance() + " " + ad);
                if (ad == 0) {
                    Integer mask = DataTypeHelper.toInt(o1.getNetMask()).compareTo(DataTypeHelper.toInt(o2.getNetMask())) * -1;
                    // System.out.println(DataTypeHelper.toInt(o1.getNetMask()) + " " + DataTypeHelper.toInt(o2.getNetMask()) + " " + mask);
                    if (mask == 0) {
                        Integer prefix = DataTypeHelper.toInt(o1.getDestinationNetwork()).compareTo(DataTypeHelper.toInt(o2.getDestinationNetwork()));
                        return prefix;
                    }
                    return mask;
                }
                return ad;
            }
        });

    }
}
