package src;

import org.jnetpcap.packet.PcapPacket;

public class Parser {

    private static String destinationMacAddress;
    private static String sourceMacAddress;
    private static String etherType;
    private static int TotalLength;
    private static String protocolType;
    private static String Identification;
    private static String srcIP;
    private static String dstIP;
    private static int srcPortNum;
    private static int dstPortNum;


    public static void parse(String s, PcapPacket packet){
        s = s.replaceAll("\\s+", " ").trim();
        destinationMacAddress = s.substring(0, 17);
        destinationMacAddress = destinationMacAddress.replace(" ", ":");
        //System.out.println("Destination MAC Address: " + destinationMacAddress);
        sourceMacAddress = s.substring(18, 35);
        sourceMacAddress = sourceMacAddress.replace(" ", ":");
        //System.out.println("Source MAC Address: " + sourceMacAddress);
        etherType = s.substring(36, 41);
        etherType = UtilititesFunctions.getEtherType(etherType.replace(" ", ""));
        //System.out.println("Type: " + etherType);
        int TotalLength = UtilititesFunctions.getDecimalFromHex(s.substring(47, 53));
        //System.out.println("Total Length: " + TotalLength);
        if(etherType.equals("Internet Protocol version 4 (IPv4)") || etherType.equals("Internet Protocol Version 6 (IPv6)")){
            protocolType = UtilititesFunctions.getProtocolType(s.substring(69, 71));
        }else{
            protocolType = etherType;
        }
        //System.out.println("Protocol: " + protocolType);
        Identification = s.substring(54, 59).replace(" ", "");
        //System.out.println("Identification: 0x" + Identification);
        srcIP = UtilititesFunctions.getIPFromHex(s.substring(77, 89));
        //System.out.println("Source IP: " + srcIP);
        dstIP = UtilititesFunctions.getIPFromHex(s.substring(90, 101));
        //System.out.println("Destination IP: " + dstIP);
        srcPortNum = UtilititesFunctions.getDecimalFromHex(s.substring(102, 108));
        //System.out.println("Source Port Number: " + srcPortNum);
        dstPortNum = UtilititesFunctions.getDecimalFromHex(s.substring(109, 115));
        if(protocolType.trim().equals("TCP")){
            protocolType = UtilititesFunctions.checkPortsForProtocols(protocolType, srcPortNum, dstPortNum);
        }
        //System.out.println("Source Port Number: " + dstPortNum);
        //System.out.println("\n-------------------------------------------------------------------\n");
    }


    public static String getProtocolType(){
        return protocolType.trim();
    }

    public static String PrintInfo(){
        return "\t\t\tSource\t\t\t\tDestination\t\t\t\tProtocol\t\t\t\n\t\t\t" + srcIP + "\t\t" + dstIP + "\t\t" + protocolType+ "\t\t\t";

    }
}
