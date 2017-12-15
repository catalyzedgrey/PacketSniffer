
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;

public class protocolFilter_ver1 {
    public static void main(String[] args) {
        StringBuilder errbuf = new StringBuilder();
        String fname = "tests/test-afs.pcap";

        Pcap pcap = Pcap.openOffline(fname, errbuf);
        if (pcap == null) {
            System.err.println(errbuf.toString());
            return;
        }

        PcapBpfProgram program = new PcapBpfProgram();
        String expression = "host 192.168.1.1";
        int optimize = 0;         // 0 = false
        int netmask = 0xFFFFFF00; // 255.255.255.0

        if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {
            System.err.println(pcap.getErr());
            return;
        }

        if (pcap.setFilter(program) != Pcap.OK) {
            System.err.println(pcap.getErr());
            return;
        }

        System.out.println("Filter set !!! : " + expression);

        pcap.close();

    }

}

