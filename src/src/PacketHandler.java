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
        Parser.parse(pcapPacket.toHexdump(pcapPacket.size(), false, false, true), pcapPacket);
        if(!controller.filterTxtField.getText().equals("")){
            if(Parser.getProtocolType().equalsIgnoreCase(controller.filterTxtField.getText())){
                controller.allPackets.add(pcapPacket);
                Platform.runLater(() -> controller.PacketsListView.getItems().add("#" + (controller.frameNo++) + " " + Parser.PrintInfo()));
            }else{
                return;
            }
        }else {
            controller.allPackets.add(pcapPacket); //Add captured packet info in both the ListView and the array of strings (allPacketsStrings)
            //have to put it here, otherwise the first case doesn't reach it -\_(^_^)_/-
            Platform.runLater(() -> controller.PacketsListView.getItems().add("#" + (controller.frameNo++) + " " + Parser.PrintInfo()));
        }
    }
}
