package src;

import javafx.application.Platform;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class PacketHandler implements PcapPacketHandler<String> {

    Controller controller;

    public PacketHandler(Controller c) {
        super();
        controller = c;
    }

    @Override
    public void nextPacket(PcapPacket pcapPacket, String s) {
        Parser.parse(pcapPacket.toHexdump(pcapPacket.size(), false, false, true));
        controller.allPackets.add(pcapPacket); //Add captured packet info in both the ListView and the array of strings (allPacketsStrings)
        Platform.runLater(() -> controller.PacketsListView.getItems().add("#" + (controller.frameNo++) + " " + Parser.PrintInfo()));
    }
}
