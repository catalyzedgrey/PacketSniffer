package src;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;

//import javax.swing.*;
//import java.awt.*;
//import java.util.ArrayList;
//import java.util.List;

import javafx.fxml.FXMLLoader;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.TextAlignment;
import javafx.stage.Stage;
import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javafx.scene.layout.StackPane;

import java.io.*;
import java.util.ArrayList;
import java.util.List;


public class main extends Application {

    private Scene scene;

    @Override
    public void start(Stage stage) throws Exception {
//        Parent root = FXMLLoader.load(getClass().getResource("sample.fxml"));
//        primaryStage.setTitle("Hello World");
//        primaryStage.setScene(new Scene(root, 300, 275));
//        primaryStage.show();
        setupUI(stage);
    }

    public void setupUI(Stage stage) {

        stage.setTitle("Menu Sample");
        scene = new Scene(new VBox(), 1280, 720);
        scene.setFill(Color.OLDLACE);

        MenuBar menuBar = new MenuBar();

        TextArea textArea = new TextArea();
        textArea.setPrefSize(1280, 720);
        textArea.setEditable(false);


        // --- Menu File
        Menu menuFile = new Menu("File");
        MenuItem startCapture = new MenuItem("StartCapture");
        startCapture.setOnAction(new EventHandler<ActionEvent>() {
            public void handle(ActionEvent t) {
                textArea.setText(capture());
            }
        });
        MenuItem add2 = new MenuItem("Test");
        add2.setOnAction(new EventHandler<ActionEvent>() {
            public void handle(ActionEvent t) {
            }
        });

        menuFile.getItems().addAll(startCapture, add2);

        // --- Menu Edit
        Menu menuEdit = new Menu("Edit");

        // --- Menu View
        Menu menuView = new Menu("View");

        menuBar.getMenus().addAll(menuFile, menuEdit, menuView);


        ((VBox) scene.getRoot()).getChildren().addAll(menuBar);

        initNetworks();

        ((VBox) scene.getRoot()).getChildren().addAll(textArea);


        stage.setScene(scene);
        stage.show();
    }

    //
//    public JFrame frame;
//    public JTextArea output;
//
//    public void render(String s []){
//        this.frame = new JFrame();
//        frame.getContentPane().setLayout(new FlowLayout());
//        frame.setSize(800, 800);
//        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//        frame.setVisible(true);
//        for (int i = 0; i < s.length; i++) {
//            JLabel l = new JLabel(s[i]);
//            l.setBounds(50,25 * (i + 1),100,30);
//            frame.add(l);
//        }
//    }
    private List<PcapIf> alldevs;
    private StringBuilder errbuf;
    private ComboBox NetworkDevicesComboBox;

    private void initNetworks() {

        alldevs = new ArrayList<>();
        errbuf = new StringBuilder(); // For any error msgs
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is " + errbuf.toString());
            return;
        }

        //Get network devices and add it to combobox
        int i = 0;
        ArrayList<String> allDevices = new ArrayList();
        for (PcapIf device : alldevs) {
            // String description = (device.getDescription() != null) ?
            //        device.getDescription() : "No description available";
            allDevices.add(String.format("#%d: [%s]", i++, (device.getDescription() != null) ? device.getDescription()
                    : device.getName()));
        }
        NetworkDevicesComboBox = new ComboBox(FXCollections.observableList(allDevices));
        /////////////////////////////////////////////////

        ((VBox) scene.getRoot()).getChildren().addAll(NetworkDevicesComboBox);
    }

    private String capture() {

        // Create a stream to hold the output
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        // IMPORTANT: Save the old System.out!
        PrintStream old = System.out;
        // Tell Java to use your special stream
        System.setOut(ps);

        PcapIf device = null;
        try {
            device = alldevs.get(NetworkDevicesComboBox.getSelectionModel().getSelectedIndex());
        } catch (Exception e) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("ERROR");
            alert.setContentText("You have not chosen a network device!");
            alert.showAndWait();
            return null;
        }

        int snaplen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return baos.toString();
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

        // Put things back
        System.out.flush();
        System.setOut(old);
        // Show what happened
        System.out.println("Here: " + baos.toString());
        return baos.toString();
    }

    public static void main(String[] args) {
        launch(args);

        //        try {
//            byte[] buffer = new byte[1000];
//
//            FileInputStream inputStream = new FileInputStream("files/trace.pcap");
//
//            // read fills buffer with data and returns
//            // the number of bytes read (which of course
//            // may be less than the buffer size, but
//            // it will never be more).
//            int total = 0;
//            int nRead = 0;
//            while ((nRead = inputStream.read(buffer)) != -1) {
//                // Convert to String so we can display it.
//                // Of course you wouldn't want to do this with
//                // a 'real' binary file.
//                System.out.println(new String(buffer));
//                total += nRead;
//            }
//
//            // Always close files.
//            inputStream.close();
//
//            System.out.println("Read " + total + " bytes");
//        } catch (FileNotFoundException ex) {
//            System.out.println(
//                    "Unable to open file '");
//        } catch (IOException ex) {
//            System.out.println(
//                    "Error reading file '");
//            // Or we could just do this:
//            // ex.printStackTrace();
//        }
//
//
//        String [] s = main.capture();
//        main m = new main();
//        m.render(s);
//    }
    }
}
