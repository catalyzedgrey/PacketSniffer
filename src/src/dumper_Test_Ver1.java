import java.io.File;
import java.nio.ByteBuffer;
import java.sql.Time;
import java.text.SimpleDateFormat;
import java.util.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;


import java.io.File;



import org.jnetpcap.Pcap;

import org.jnetpcap.PcapDLT;

import org.jnetpcap.PcapDumper;

import org.jnetpcap.PcapHeader;

import org.jnetpcap.nio.JBuffer;

import org.jnetpcap.packet.format.FormatUtils;

//merge with the main program code

public class dumper_Test_Ver1 {
        public static void main(String[] args) {
                //create a dummy packet;copied
                final JBuffer packet = new JBuffer(FormatUtils.toByteArray(""
                        + "0007e914 78a20010 7b812445 080045c0" + "00280005 0000ff11 70e7c0a8 62dec0a8"
                        + "65e906a5 06a50014 e04ac802 000c0002" + "00000002 00060000 00000000"));

                //giving your packet a header;which will be passed to the dumper method later
                final PcapHeader h = new PcapHeader(packet.size(), packet.size());
                //pcap capturing packet is to be here instead of creating a dummy packet session
                final int dlt = PcapDLT.EN10MB.value;
                final int snaplen = 64 * 1024;
                final Pcap pcap = Pcap.openDead(dlt, snaplen);
                if (pcap == null) {
                        System.err.printf("Error while dummy capture: " + pcap.getErr());
                        return;
                }
                //**calling pcapdumper ;it's our desired part
                //creating a file
                final String saved_packets = "tmp-capture-file.pcap";
                final File file = new File(saved_packets); //to save packets in(pcap dumper parameter)
                final PcapDumper dumper = pcap.dumpOpen(saved_packets); //calling pcap dumper to open the created file

            System.out.println("enter the number of packets to save");
            Scanner s=new Scanner(System.in);
            int num=s.nextInt();
                for (int i = 0; i <=num; i++) //to be replaced with a button or a better idea
                {
                        dumper.dump(h, packet); //save num packets with the initialized header

                }
                dumper.close();
                pcap.close();

        }
}
