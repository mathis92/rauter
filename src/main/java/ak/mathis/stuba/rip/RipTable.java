/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ak.mathis.stuba.rip;

import java.util.ArrayList;
import java.util.List;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.headers.IpV4Address;

/**
 *
 * @author martinhudec
 */
public class RipTable implements Runnable{

    List<RipTableItem> ripNetworkTable;
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(RipTable.class);

    public RipTable() {
        ripNetworkTable = new ArrayList<>();
        logger.info("[RipTable] start");
    }
    
    
    
    @Override
    public void run() {

    }
    public void addRipNetwork(IpV4Address network, IpV4Address netMask){
        logger.info("[RipTable] adding ripNetwork " + network );
        ripNetworkTable.add(new RipTableItem(network, netMask));
    }

    public List<RipTableItem> getRipNetworkList() {
        return ripNetworkTable;
    }
    
    
}
