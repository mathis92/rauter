/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.router;

import java.io.IOException;
import java.util.logging.Level;
import javax.swing.table.DefaultTableModel;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.arp.ArpTableItem;
import sk.mathis.stuba.equip.DataTypeHelper;
import sk.mathis.stuba.equip.PacketReceiver;
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
    RootingTablePanel routingTablePanel;
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
            fillRootingTable();

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
        routingTablePanel = new RootingTablePanel(manager);
        gui.getMainTabPane().add(routingTablePanel).setName("RootingTable");
        gui.getMainTabPane().setTitleAt(2, "RootingTable");
        fillPortManagementPanel();
    }

    public void fillPortManagementPanel() {
        portManagementPanel.getPortComboBox().removeAllItems();
        for (PacketReceiver port : manager.getAvailiablePorts()) {
            if (port.getIpAddress() == null) {
                portManagementPanel.getPortComboBox().addItem(port);
            }
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
            data[1] = (port.getMacAddress() == null) ? "error" : DataTypeHelper.macAdressConvertor(port.getMacAddress());
            data[2] = (port.getIpAddress() == null) ? "not set" : DataTypeHelper.ipAdressConvertor(port.getIpAddress());

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
            data[1] = DataTypeHelper.ipAdressConvertor(arpItem.getIpAddress());
            data[2] = (arpItem.getMacAddress() != null) ? DataTypeHelper.macAdressConvertor(arpItem.getMacAddress()) : "currently resolving";
            data[3] = arpItem.getTimeOfAdd();
            arpTableModel.addRow(data);
        }
        arpTablePanel.getArpTable().setModel(arpTableModel);
    }

    public void fillRootingTable() {
        Object[] data = new Object[6];
        DefaultTableModel routingTableModel;
        routingTableModel = (DefaultTableModel) routingTablePanel.getRootingTabel().getModel();
        routingTableModel.setRowCount(0);

        int i = 0;

        for (RoutingTableItem route : manager.getRoutingTable().getRouteList()) {
            data[0] = route.getType();
            data[1] = route.getCidrRange();
            data[2] = DataTypeHelper.ipAdressConvertor(route.getNetMask());
            data[3] = DataTypeHelper.ipAdressConvertor(route.getGateway());
            if (route.getType().equals("C")) {
                data[4] = route.getPort().getPortName();
            } else {
                data[4] = DataTypeHelper.ipAdressConvertor(route.getPort().getIpAddress());
            }
            data[5] = route.getAdministrativeDistance();
            routingTableModel.addRow(data);
        }
        routingTablePanel.getRootingTabel().setModel(routingTableModel);
    }

    public void setPortDetails(PacketReceiver selectedPort, String ipAddress, String subnetMask) {
        for (PacketReceiver port : manager.getAvailiablePorts()) {
            if (port.getPortName().equals(selectedPort.getPortName())) {
                port.setPortDetails(DataTypeHelper.ipAddressToByte(ipAddress), DataTypeHelper.ipAddressToByte(subnetMask));
            }
        }
    }

    public RouterManager getManager() {
        return manager;
    }

}
