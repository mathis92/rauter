/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.routingTable;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonReaderFactory;
import javax.json.JsonValue;
import javax.json.JsonWriter;
import javax.json.JsonWriterFactory;
import javax.json.stream.JsonGenerator;
import org.apache.commons.net.util.SubnetUtils;
import sk.mathis.stuba.arp.ArpTableItem;
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.Packet;
import sk.mathis.stuba.equip.PacketReceiver;
import sk.mathis.stuba.exceptions.PortNotFoundException;
import sk.mathis.stuba.router.AppGUIController;
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

    public void addRoutesFromConfig() {
        System.out.println("idem pridavat statiky");
        try {
            JsonArray ja = readStaticRoutesConfig();
            for (JsonValue jv : ja) {
                addStaticRoute(((JsonObject) jv).getString("network"), ((JsonObject) jv).getString("subnetMask"), ((JsonObject) jv).getString("nextHop"), false);
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(RoutingTable.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void addRipRoute(byte[] network, byte[] subnetMask, byte[] nextHop, PacketReceiver ripOutPort, Integer metric) {
        RoutingTableItem newRipRoute = new RoutingTableItem(network, subnetMask, nextHop, ripOutPort, 120, metric, "R");
        if (!routeList.contains(newRipRoute)) {
            routeList.add(newRipRoute);
        }
    }

    public void addStaticRoute(String network, String subnetMask, String nextHop, Boolean fromGUI) {
        PacketReceiver staticOutPort = null;
        for (PacketReceiver port : manager.getAvailiablePorts()) {
            if (Arrays.equals(resolveNetwork(port.getIpAddress(), port.getSubnetMask()), resolveNetwork(DataTypeHelper.ipAddressToByteFromString(nextHop), DataTypeHelper.ipAddressToByteFromString(subnetMask)))) {
                staticOutPort = port;
            }
        }
        try {
            RoutingTableItem newStaticRoute = new RoutingTableItem(DataTypeHelper.ipAddressToByteFromString(network), DataTypeHelper.ipAddressToByteFromString(subnetMask), DataTypeHelper.ipAddressToByteFromString(nextHop), staticOutPort, 1, "S");
            routeList.add(newStaticRoute);
            if (fromGUI) {
                addStaticRouteToConfig(network, subnetMask, nextHop);
            }
        } catch (Exception e) {
            try {
                throw new PortNotFoundException("port not found");
            } catch (PortNotFoundException ex) {
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
                        if (route.getType().equals("C")) {
                            added = 1;
                            route.updateRouteData(resolveNetwork(port.getIpAddress(), port.getSubnetMask()), port.getSubnetMask(), port.getIpAddress(), port, 0, "C");
                        }
                    }
                }
                if (added == 0) {
                    RoutingTableItem newDirectlyConnected = new RoutingTableItem(resolveNetwork(port.getIpAddress(), port.getSubnetMask()), port.getSubnetMask(), port.getIpAddress(), port, 1, "C");
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

    public JsonArray readStaticRoutesConfig() throws FileNotFoundException {
        JsonReaderFactory jrf = Json.createReaderFactory(null);

        FileInputStream fis = new FileInputStream(new File("F:/Router/staticRoutes.txt"));

        try (JsonReader jr = jrf.createReader(fis, Charset.defaultCharset())) {
            JsonObject jo = jr.readObject();
            JsonArray ja = jo.getJsonArray("staticRoutes");
            return ja;
        }
    }

    public void addStaticRouteToConfig(String network, String subnetMask, String nextHop) {

        FileOutputStream fos;
        try {
            JsonObjectBuilder extObject = Json.createObjectBuilder();
            JsonArrayBuilder arrObject = Json.createArrayBuilder();
            JsonArray ja = readStaticRoutesConfig();

            fos = new FileOutputStream("F:/Router/staticRoutes.txt");

            Map<String, Object> jwfConfig = new HashMap<>();
            jwfConfig.put(JsonGenerator.PRETTY_PRINTING, true);
            JsonWriterFactory jwf = Json.createWriterFactory(jwfConfig);
            try (JsonWriter writer = jwf.createWriter(fos)) {
                for (JsonValue jv : ja) {
                    JsonObject jo = (JsonObject) jv;
                    JsonObjectBuilder job = Json.createObjectBuilder();
                    for (Map.Entry<String, JsonValue> entry : jo.entrySet()) {
                        job.add(entry.getKey(), entry.getValue());
                    }
                    arrObject.add(job);
                }

                extObject.add("network", network);
                extObject.add("subnetMask", subnetMask);
                extObject.add("nextHop", nextHop);
                arrObject.add(extObject);

                JsonObjectBuilder jo = Json.createObjectBuilder();
                jo.add("staticRoutes", arrObject);
                writer.writeObject(jo.build());
            }
        } catch (FileNotFoundException ex) {
            java.util.logging.Logger.getLogger(AppGUIController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void orderRoutingTable() {

        Collections.sort(routeList, new Comparator<RoutingTableItem>() {

            @Override
            public int compare(RoutingTableItem o1, RoutingTableItem o2) {
                Integer ad = o1.getAdministrativeDistance().compareTo(o2.getAdministrativeDistance());
                //System.out.println("AD " + o1.getAdministrativeDistance() + " " + o2.getAdministrativeDistance() + " " + ad);
                if (ad == 0) {
                    Integer mask = ((Integer) DataTypeHelper.convertNetmaskToCIDR(o1.getNetMask())).compareTo((Integer) DataTypeHelper.convertNetmaskToCIDR(o2.getNetMask())) * -1;
                    //System.out.println("MASK " + ((Integer) DataTypeHelper.convertNetmaskToCIDR(o1.getNetMask())) + " " + ((Integer) DataTypeHelper.convertNetmaskToCIDR(o2.getNetMask())) + " " + mask);
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
