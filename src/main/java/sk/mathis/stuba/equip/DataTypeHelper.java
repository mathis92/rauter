/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.equip;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import sk.mathis.stuba.analysers.Analyser;

/**
 *
 * @author Mathis
 */
public class DataTypeHelper {

    public static Map<Integer, String> tcpMap;
    public static Map<Integer, String> udpMap;
    public static Map<Integer, String> portMap;
    public static String portFilePath = null;
    public static ArrayList<String> otherPorts = new ArrayList<>();
    static final ClassLoader loader = DataTypeHelper.class.getClassLoader();

    public static Integer singleToInt(byte singleByte) {
        Integer result = 0;
        result = (singleByte & 0xff);
        return result;

    }

    public static Integer toInt(byte[] byteArray) {
        Integer result = 0;

        for (int i = 0; i < byteArray.length - 1; i++) {
            result = ((byteArray[i] & 0xff) << 8) | ((byteArray[i + 1] & 0xff));

        }
        return result;

    }

    public static String bToString(byte singleByte) {
        StringBuilder newString = new StringBuilder();
        newString.append(String.format("%02X", singleByte));
        return newString.toString();
    }

    public static String macAdressConvertor(byte[] macAdressByteArray) {
        String macAdress = null;
        for (int i = 0; i < 6; i++) {
            if (macAdress != null) {
                macAdress = macAdress + ":" + DataTypeHelper.bToString(macAdressByteArray[i]);
            } else {
                macAdress = DataTypeHelper.bToString(macAdressByteArray[i]);
            }
        }
        return macAdress;

    }

    public static String getUdpPortName(Integer port) {

        String portName = udpMap.get(port);
        if (portName == null) {
            portName = "unknown";
        }

        return portName;
    }

    public static String getTcpPortName(Integer port) {

        String portName = tcpMap.get(port);
        if (portName == null) {
            portName = "unknown";
        }
        return portName;
    }

    public static String ipAdressConvertor(byte[] ipAdressByteArray) {
        //System.out.println(ipAdressByteArr);
        String ipAdress = null;
        for (int i = 0; i < 4; i++) {
            if (ipAdress != null) {
                ipAdress = ipAdress + "." + DataTypeHelper.singleToInt(ipAdressByteArray[i]);
            } else {
                ipAdress = DataTypeHelper.singleToInt(ipAdressByteArray[i]).toString();
            }
        }
        return ipAdress;

    }

    public static Integer getIhl(byte rByte) {
        Integer output = 0;
        output = DataTypeHelper.singleToInt(rByte);
        output = output & 0x0F;
        return output;
    }

    public static byte[] parseStringMacAddress(String stringMac) {
        byte[] macAddress = new byte[6];
        String[] stringMacArray = stringMac.split(":");
        for (int i = 0; i < 6; i++) {
            macAddress[i] = (byte) Integer.parseInt(stringMacArray[i], 16);
        }

        return macAddress;
    }

    public static byte[] parseStringIpAddress(String stringIp) {
        byte[] ipAddress = new byte[4];
        String[] stringIpAddress = stringIp.split(":");
        for (int i = 0; i < 4; i++) {
            ipAddress[i] = (byte) Integer.parseInt(stringIpAddress[i], 16);
        }

        return ipAddress;
    }

    public static void scanPortsFile() throws FileNotFoundException, IOException {
        try {
            try {
                BufferedReader reader = null;
                tcpMap = new HashMap<>();
                udpMap = new HashMap<>();

                InputStream is = DataTypeHelper.class.getResourceAsStream("/sk/mathis/stuba/files/ports.txt");
                reader = new BufferedReader(new InputStreamReader(is));
                String line = reader.readLine();
                while (line != null) {
                    if (line != null) {
                        line = line.replaceAll("\t", " ").replaceAll("  ", " ");
                        String[] protocolName = line.split(" ");
                        String[] protocolCode = protocolName[1].split("/");
                        //  System.out.println(protocolName[0] + " -> " + protocolCode[0] + " -> " + protocolCode[1]);
                        if (protocolCode[1].toString().equalsIgnoreCase("udp")) {
                            udpMap.put(Integer.parseInt(protocolCode[0]), protocolName[0]);

                        } else if (protocolCode[1].toString().equalsIgnoreCase("tcp")) {
                            tcpMap.put(Integer.parseInt(protocolCode[0]), protocolName[0]);

                        }
                    }
                    line = reader.readLine();
                }
                reader.close();

            } catch (FileNotFoundException ex) {
                Logger.getLogger(Analyser.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (IOException ex) {
            Logger.getLogger(Analyser.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public static void scanProtocolFile() {
        try {
            try {
                BufferedReader reader = null;
                portMap = new HashMap<>();
                InputStream is = DataTypeHelper.class.getResourceAsStream("/sk/mathis/stuba/files/protocols.txt");
                reader = new BufferedReader(new InputStreamReader(is));
                String line = reader.readLine();
                while (line != null) {
                    if (line != null) {
                        line = line.replaceAll(" ", "");
                        String[] protocolName = line.split("/");
                        // System.out.println(protocolName[0] + "->" + protocolName[1]);
                        portMap.put(Integer.parseInt(protocolName[0]), protocolName[1]);
                    }
                    line = reader.readLine();
                }
                reader.close();
            } catch (FileNotFoundException ex) {
                Logger.getLogger(Analyser.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (IOException ex) {
            Logger.getLogger(Analyser.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public final static byte[] ipAddressToByteFromString(String addr){
        InetAddress ipAddress = null;
        try {
            ipAddress = InetAddress.getByName(addr);
        } catch (UnknownHostException ex) {
            Logger.getLogger(DataTypeHelper.class.getName()).log(Level.SEVERE, null, ex);
        }
        return ipAddress.getAddress();
    }
    
    public final static byte[] ipAddressToByte(String addr) {
        
      // Convert the TCP/IP address string to an integer value
        int ipInt = parseNumericAddress(addr);
        if (ipInt == 0) {
            return null;
        }

      // Convert to bytes
        byte[] ipByts = new byte[4];

        ipByts[3] = (byte) (ipInt & 0xFF);
        ipByts[2] = (byte) ((ipInt >> 8) & 0xFF);
        ipByts[1] = (byte) ((ipInt >> 16) & 0xFF);
        ipByts[0] = (byte) ((ipInt >> 24) & 0xFF);

      // Return the TCP/IP bytes
        return ipByts;
    }
    
    public final static int parseNumericAddress(String ipaddr) {
  
    //  Check if the string is valid
    
    if ( ipaddr == null || ipaddr.length() < 7 || ipaddr.length() > 15)
      return 0;
      
    //  Check the address string, should be n.n.n.n format
    
    StringTokenizer token = new StringTokenizer(ipaddr,".");
    if ( token.countTokens() != 4)
      return 0;

    int ipInt = 0;
    
    while ( token.hasMoreTokens()) {
      
      //  Get the current token and convert to an integer value
      
      String ipNum = token.nextToken();
      
      try {
        
        //  Validate the current address part
        
        int ipVal = Integer.valueOf(ipNum).intValue();
        if ( ipVal < 0 || ipVal > 255)
          return 0;
          
        //  Add to the integer address
        
        ipInt = (ipInt << 8) + ipVal;
      }
      catch (NumberFormatException ex) {
        return 0;
      }
    }
    
    //  Return the integer address
    
    return ipInt;
  }
    
    

    public static String getStringFromArray() {
        String output = null;
        if (otherPorts.isEmpty()) {
            output = " -- ";
        }
        for (String temp : otherPorts) {
            if (output == null) {
                output = temp;
            } else {
                output += ", " + temp;
            }
        }

        return output;
    }

    public static String getIcmpType(Integer type) throws FileNotFoundException {
        String typeMessage = null;
        try {

            FileReader file = new FileReader("\\files\\IcmpTypes.txt");
            Scanner scan = new Scanner(file);
            while (scan.hasNext()) {
                if (scan.hasNextInt()) {
                    if (scan.nextInt() == type) {
                        while (scan.hasNextInt() != true) {
                            if (typeMessage == null) {
                                typeMessage = scan.next();
                            } else {
                                typeMessage += " " + scan.next();
                            }
                        }
                        break;
                    }
                } else {
                    scan.next();
                }
            }
            file.close();
        } catch (IOException e) {
        }

        return typeMessage;
    }
}
