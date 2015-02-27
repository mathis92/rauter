/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.router;

import java.io.IOException;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.equip.Port;

/**
 *
 * @author martinhudec
 */
public class AppGUIController implements Runnable {

    private AppGUI gui;
    RouterManager manager;
    Integer availablePortsCount = 0;
    private static final Logger logger = LoggerFactory.getLogger(AppGUIController.class);

    public AppGUIController(AppGUI gui) throws IOException {
        manager = new RouterManager();
        manager.start();
        logger.debug("VAJSA");
        this.gui = gui;
        updateTextArea();
    }

    @Override
    public void run() {
        while (true) {            
            
        }
    }

    public void updateTextArea() {
        gui.getjTextArea1().removeAll();
        for (Port port : manager.getAvailiablePorts()) {
            gui.getjTextArea1().append(port.getPortName() + " " + port.getPcapIfPort().getAddresses() + " " + port.getPcapIfPort().getDescription() + "\n");
        }

    }

}
