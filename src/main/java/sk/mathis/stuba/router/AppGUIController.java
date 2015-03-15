/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.router;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
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
import javax.swing.table.DefaultTableModel;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.arp.ArpTableItem;
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.PacketReceiver;
import sk.mathis.stuba.routingTable.RouteTypeEnum;
import sk.mathis.stuba.routingTable.RoutingTable;
import sk.mathis.stuba.routingTable.RoutingTableItem;

/**
 *
 * @author martinhudec
 */
public class AppGUIController implements Runnable {

    private AppGUI gui;
    RouterManager manager;
    Integer availablePortsCount = 0;
    ArpTablePanel arpTablePanel;
    PortManagementPanel portManagementPanel;
    RoutingTablePanel routingTablePanel;
    StaticRoutesPanel staticRoutesPanel;
    private static final Logger logger = LoggerFactory.getLogger(AppGUIController.class);

    public AppGUIController(AppGUI gui) throws IOException {
        manager = new RouterManager();
        manager.start();

        this.gui = gui;
        initialize();
    }

    @Override
    public void run() {
        while (true) {

            fillArpTable();
            fillPortTable();
            fillRoutingTable();

            try {
                Thread.sleep(500);
            } catch (InterruptedException ex) {
                java.util.logging.Logger.getLogger(AppGUIController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void initialize() {
        arpTablePanel = new ArpTablePanel(manager);
        gui.getMainTabPane().add(arpTablePanel).setName("ArpTable");
        gui.getMainTabPane().setTitleAt(0, "ArpTable");
        portManagementPanel = new PortManagementPanel(this);
        gui.getMainTabPane().add(portManagementPanel).setName("PortManagement");
        gui.getMainTabPane().setTitleAt(1, "PortManagement");
        routingTablePanel = new RoutingTablePanel(manager);
        gui.getMainTabPane().add(routingTablePanel).setName("RoutingTable");
        gui.getMainTabPane().setTitleAt(2, "RoutingTable");
        staticRoutesPanel = new StaticRoutesPanel(manager);
        gui.getMainTabPane().add(staticRoutesPanel).setName("StaticRoutesPanel");
        gui.getMainTabPane().setTitleAt(3, "StaticRoutesPanel");
        fillPortManagementPanel();
        manager.getRoutingTable().addRoutesFromConfig();
    }

    public void fillPortManagementPanel() {
        portManagementPanel.getPortComboBox().removeAllItems();
        for (PacketReceiver port : manager.getAvailiablePorts()) {
            if (port.getIpAddressByte() == null) {
                portManagementPanel.getPortComboBox().addItem(port);
            }
        }
        try {
            JsonArray ja = readIpAddressConfig();
            for (JsonValue jv : ja) {
                System.out.println(((JsonObject) jv).get("portName"));
                this.setPortDetails(((JsonObject) jv).getString("portName"), ((JsonObject) jv).getString("ipAddress"), ((JsonObject) jv).getString("netMask"), false);
            }
        } catch (FileNotFoundException ex) {
            java.util.logging.Logger.getLogger(AppGUIController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void fillPortTable() {
        Object[] data = new Object[5];
        DefaultTableModel portTableModel;
        portTableModel = (DefaultTableModel) portManagementPanel.getPortTable().getModel();
        portTableModel.setRowCount(0);

        int i = 0;
        for (PacketReceiver port : manager.getAvailiablePorts()) {
            data[0] = port.getPortName();
            data[1] = (port.getMacAddressByte() == null) ? "error" : DataTypeHelper.macAdressConvertor(port.getMacAddressByte());
            data[2] = (port.getIpAddressByte() == null) ? "not set" : DataTypeHelper.ipAdressConvertor(port.getIpAddressByte());

            data[3] = "ZATIAL MFP";
            data[4] = (port.getSubnetMask() == null) ? "not set" : DataTypeHelper.ipAdressConvertor(port.getSubnetMask());

            portTableModel.addRow(data);

        }
        portManagementPanel.getPortTable().setModel(portTableModel);
    }

    public void fillArpTable() {
        Object[] data = new Object[5];
        DefaultTableModel arpTableModel;
        arpTableModel = (DefaultTableModel) arpTablePanel.getArpTable().getModel();
        arpTableModel.setRowCount(0);

        int i = 0;
        for (ArpTableItem arpItem : manager.getArpTable().getArpTableList()) {
            data[0] = arpItem.getPort().getPortName();
            data[1] = DataTypeHelper.ipAdressConvertor(arpItem.getIpAddressByte());
            data[2] = (arpItem.getMacAddress().getMacByte() != null) ? arpItem.getMacAddress().toString() : "currently resolving";
            data[3] = arpItem.getTimeOfAdd();
            arpTableModel.addRow(data);
        }
        arpTablePanel.getArpTable().setModel(arpTableModel);
    }

    public void fillRoutingTable() {
        Object[] data = new Object[5];
        DefaultTableModel routingTableModel;
        routingTableModel = (DefaultTableModel) routingTablePanel.getRootingTabel().getModel();
        routingTableModel.setRowCount(0);

        int i = 0;

        for (RoutingTableItem route : manager.getRoutingTable().getRouteList()) {
            data[0] = route.getType();
            data[1] = route.getCidrRange();
            data[2] = DataTypeHelper.ipAdressConvertor(route.getNetMask());
            //data[3] = route.getGateway().toString();
            if (route.getType() == RouteTypeEnum.directlyConnectedRoute) {
                data[3] = route.getPort().getPortName();
            } else {
                data[3] = route.getGateway().toString();
            }
            data[4] = route.getAdministrativeDistance()+"/"+route.getMetric();
            routingTableModel.addRow(data);
        }
        routingTablePanel.getRootingTabel().setModel(routingTableModel);
    }

    public void setPortDetails(String portName, String ipAddress, String subnetMask, Boolean fromGUI) {
        for (PacketReceiver port : manager.getAvailiablePorts()) {
            if (port.getPortName().equals(portName)) {
                port.setPortDetails(DataTypeHelper.ipAddressToByte(ipAddress), DataTypeHelper.ipAddressToByte(subnetMask));
                if (fromGUI) {
                    this.addPortDetailsToConfig(portName, ipAddress, subnetMask);
                }
            }
        }
    }

    public JsonArray readIpAddressConfig() throws FileNotFoundException {
        JsonReaderFactory jrf = Json.createReaderFactory(null);

        FileInputStream fis = new FileInputStream(new File("F:/Router/configIP.txt"));

        try (JsonReader jr = jrf.createReader(fis, Charset.defaultCharset())) {
            JsonObject jo = jr.readObject();
            JsonArray ja = jo.getJsonArray("ipAddress");
            return ja;
        }
    }
 
    public void removeExtension(Object meno) {
        FileOutputStream fos = null;
        logger.debug("idem vymazavat meno " + meno);
        try {
            JsonObjectBuilder extObject = Json.createObjectBuilder();
            JsonArrayBuilder arrObject = Json.createArrayBuilder();
            JsonArray ja = readIpAddressConfig();

            fos = new FileOutputStream("/Users/martinhudec/Desktop/users.txt");
            Map<String, Object> jwfConfig = new HashMap<>();
            jwfConfig.put(JsonGenerator.PRETTY_PRINTING, true);
            JsonWriterFactory jwf = Json.createWriterFactory(jwfConfig);
            try (JsonWriter writer = jwf.createWriter(fos)) {
                for (JsonValue jv : ja) {
                    JsonObject jo = (JsonObject) jv;
                    JsonObjectBuilder job = null;
                    if (!jo.getString("extension").equals(meno)) {
                        logger.debug("pridal som " + jo.getString("extension"));
                        job = Json.createObjectBuilder();
                        job.add("userName", jo.getString("userName"));
                        job.add("password", jo.getString("password"));
                        job.add("extension", jo.getString("extension"));

                    }
                    if (job != null) {
                        arrObject.add(job);
                    }
                }

                JsonObjectBuilder jo = Json.createObjectBuilder();
                jo.add("users", arrObject);
                writer.writeObject(jo.build());
            }
        } catch (FileNotFoundException ex) {
            java.util.logging.Logger.getLogger(AppGUIController.class
                    .getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fos.close();

            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(AppGUIController.class
                        .getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void addPortDetailsToConfig(String portName, String ipAddress, String netMask) {

        FileOutputStream fos;
        try {
            JsonObjectBuilder extObject = Json.createObjectBuilder();
            JsonArrayBuilder arrObject = Json.createArrayBuilder();
            JsonArray ja = readIpAddressConfig();

            fos = new FileOutputStream("F:/Router/configIP.txt");

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

                extObject.add("portName", portName);
                extObject.add("ipAddress", ipAddress);
                extObject.add("netMask", netMask);
                arrObject.add(extObject);

                JsonObjectBuilder jo = Json.createObjectBuilder();
                jo.add("ipAddress", arrObject);
                writer.writeObject(jo.build());
            }
        } catch (FileNotFoundException ex) {
            java.util.logging.Logger.getLogger(AppGUIController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

       
    
    
    
    public RouterManager getManager() {
        return manager;
    }

}
