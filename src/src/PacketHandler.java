package src;

import javafx.application.Platform;
import org.jnetpcap.packet.*;

public class PacketHandler implements PcapPacketHandler<String> {

    Controller controller;
    Parser parser;

    public PacketHandler(Controller c) {
        super();
        controller = c;
        parser = new Parser();
    }

    @Override
    public void nextPacket(PcapPacket pcapPacket, String s) {
        //Parser.parse( pcapPacket.toHexdump(pcapPacket.size(), false, false, true), pcapPacket);
        /*
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
        }*/
        Platform.runLater(() -> {
            controller.allPackets.add(pcapPacket);
            controller.observablePackets.add("#" + (controller.frameNo++) + " " + parser.PrintInfo(pcapPacket));
        });
    }

}
