/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.PcapIf;

/**
 *
 * @author martinhudec
 */
public class Port {

    private String portName;
    private PcapIf port;
    private String ip = "192.168.56.200";
    private byte[] ipAddress = DataTypeHelper.ipAddressToByte(ip);
    private byte[] macAddress;
    private byte[] subnetMask;

    public Port(String portName, PcapIf port) {
        this.port = port;
        try {
            macAddress = port.getHardwareAddress();
        } catch (IOException ex) {
            Logger.getLogger(Port.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.portName = portName;
    }

    public PcapIf getPcapIfPort() {
        return port;
    }

    public String getPortName() {
        return portName;
    }

    public byte[] getIpAddress() {
        return ipAddress;
    }

    public PcapIf getPort() {
        return port;
    }

    public byte[] getSubnetMask() {
        return subnetMask;
    }

    public byte[] getMacAddress() {
        return macAddress;
    }

    public void setIpAddress(byte[] ipAddress) {
        this.ipAddress = ipAddress;
    }

    public void setSubnetMask(byte[] subnetMask) {
        this.subnetMask = subnetMask;
    }
}
