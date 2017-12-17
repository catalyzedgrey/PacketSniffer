package src;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.Arrays;
import java.util.stream.IntStream;


public class UtilititesFunctions {

    private static int[] HTTPPorts = {80, 3128,3132,5985,8080,8088,11371,1900,2869,2710};

    public static int getDecimalFromHex (String HexNeededToBeConvertedTodec){
        HexNeededToBeConvertedTodec = HexNeededToBeConvertedTodec.replace(" ", "");
        int ConvertedHex = Integer.parseInt(HexNeededToBeConvertedTodec, 16);
        return ConvertedHex;
    }
    public static String getIPFromHex(String HexNeededToBeTurnedToIP){
        HexNeededToBeTurnedToIP = HexNeededToBeTurnedToIP.replace(" ", "");
        String splittedString[] = new String[4];
        for (int i = 0, j = 0; i < HexNeededToBeTurnedToIP.length(); i+=2, j++){
            splittedString[j] = "" + HexNeededToBeTurnedToIP.charAt(i) + HexNeededToBeTurnedToIP.charAt(i + 1);
        }
        String IP = "";
        for(int i = 0; i < splittedString.length; i++){
            if(i == 0)
                IP = IP + getDecimalFromHex(splittedString[i]);
            else
                IP = IP + "." + getDecimalFromHex(splittedString[i]);
        }
        return IP;
    }
    public static String getEtherType(String EtherTypeHexStringified){
        String line = "";
        try {
            String path = System.getProperty("user.dir");
            BufferedReader br = new BufferedReader(new FileReader(path + "\\Resources\\EtherType.txt"));
            while((line = br.readLine()) != null){
                String s = line.split("\t\t")[0];
                if(s.equals(EtherTypeHexStringified)){
                    EtherTypeHexStringified = line.split("\t\t")[1];
                    return EtherTypeHexStringified;
                }
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return EtherTypeHexStringified;
    }

    public static String getProtocolType(String ProtocolTypeHexStringified) {
        String line = "";
        int dec = getDecimalFromHex(ProtocolTypeHexStringified);
        try {
            String path = System.getProperty("user.dir");
            BufferedReader br = new BufferedReader(new FileReader(path + "\\Resources\\ProtocolNumbers.txt"));
            while((line = br.readLine()) != null){
                String s = line.split("\t\t")[0];
                if(s.equals(Integer.toString(dec))){
                    ProtocolTypeHexStringified = line.split("\t\t")[1];
                    return ProtocolTypeHexStringified;
                }
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return ProtocolTypeHexStringified;
    }

    public static String checkPortsForProtocols(String protocolType, int srcPortNum, int dstPortNum) {
        //80,3128,3132,5985,8080,8088,11371,1900,2869,2710 for HTTP
        if(IntStream.of(HTTPPorts).anyMatch(x -> x == srcPortNum) || IntStream.of(HTTPPorts).anyMatch(x -> x == dstPortNum)){
            protocolType = "HTTP";
        }
        return protocolType;
    }
}
