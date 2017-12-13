package src;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class PacketHandler implements PcapPacketHandler<String> {
    @Override
    public void nextPacket(PcapPacket pcapPacket, String s) {
        Parser.parse(pcapPacket.toHexdump(pcapPacket.size(), false, false, true));
        System.out.println(pcapPacket);
    }
}
