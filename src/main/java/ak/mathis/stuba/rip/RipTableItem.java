/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ak.mathis.stuba.rip;

import java.util.Date;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.headers.IpV4Address;

/**
 *
 * @author martinhudec
 */
public class RipTableItem {
    IpV4Address networkAddress;
    IpV4Address netMaskAddress;
    Date flushTimer; 
    Date invalidTimer;
    
private static final org.slf4j.Logger logger = LoggerFactory.getLogger(RipTableItem.class);
    public RipTableItem(IpV4Address networkAddress, IpV4Address netMaskAddress) {
        this.networkAddress = networkAddress;
        this.netMaskAddress = netMaskAddress;
    }

    public IpV4Address getNetMaskAddress() {
        return netMaskAddress;
    }

    public IpV4Address getNetworkAddress() {
        return networkAddress;
    }

    public Date getFlushTimer() {
        return flushTimer;
    }

    @Override
    public String toString() {
         super.toString(); //To change body of generated methods, choose Tools | Templates.
        return networkAddress + " -> " + netMaskAddress;
    }
    
    public boolean fitToNetwork(IpV4Address network) {
        boolean fit = IpV4Address.equals(networkAddress,
                network.checkRange(netMaskAddress));
        logger.info("[FIT to network check] " + " src IP: " + network + " network:  " + networkAddress + " -> " + netMaskAddress + "RESULT: " + fit );
        return fit;
    }

}
