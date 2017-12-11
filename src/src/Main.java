package src;

import javafx.fxml.FXML;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import javafx.application.Application;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class Main extends Application {

    private Scene scene;

    @Override
    public void start(Stage stage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("../main.fxml"));
        scene = new Scene(root, 1280, 720);
        scene.setFill(Color.OLDLACE);
        stage.setTitle("ABC PACKET SNIFFER");
        stage.setScene(scene);
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
