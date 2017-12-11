package src;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class main {

    public JFrame frame;
    public JTextArea output;

    public void render(String s []){
        this.frame = new JFrame();
        frame.getContentPane().setLayout(new FlowLayout());
        frame.setSize(800, 800);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setVisible(true);
        for (int i = 0; i < s.length; i++) {
            JLabel l = new JLabel(s[i]);
            l.setBounds(50,25 * (i + 1),100,30);
            frame.add(l);
        }
    }

    public static String[] capture(){
        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder(); // For any error msgs
        String [] s = new String[10];
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is " + errbuf.toString());
            return s;
        }
        System.out.println("Network devices found:");
        int i = 0;
        for (PcapIf device : alldevs) {
            String description = (device.getDescription() != null) ? device
                    .getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(),
                    description);
        }
        PcapIf device = alldevs.get(1);
        System.out.printf("\nChoosing '%s' on your behalf:\n",
                (device.getDescription() != null) ? device.getDescription()
                        : device.getName());
        int snaplen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return s;
        }

        final int[] j = {0};
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                Ip4 ip = new Ip4();
                if (packet.hasHeader(ip) == false) {
                    return; // Not IP packet
                }
                /*s[j[0]] = packet.toString();
                System.out.println(s[j[0]]);
                System.out.print("\n\n\n\n\n-------------------------------------------------------\n\n\n\n");
                j[0]++;*/
                System.out.println(packet);
            }
        };
        pcap.loop(10, jpacketHandler, "jNetPcap");
        pcap.close();
        return s;
    }

    public static void main(String[] args){
        String [] s = main.capture();
        main m = new main();
        m.render(s);
    }
}
