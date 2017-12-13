package src;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

public class Controller {
    private List<PcapIf> alldevs;
    private StringBuilder errbuf;
    @FXML
    private ComboBox netDevicesCombo;
    @FXML
    private Button CaptureBtn;
    @FXML
    private TextArea PacketInfoTextArea;
    @FXML
    private ListView PacketsListView;
    @FXML
    private Button pcapSaveBtn;
    @FXML
    private TextField filterTxtField;

    private Boolean Capturing = false;

    private ArrayList<String> allPackets;

    private int frameNo;

    private Pcap pcap;

    public void initialize() {
        CaptureBtnNormalStyle();
        allPackets = new ArrayList<>();
        initNetworks();
    }

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
        for (PcapIf device : alldevs) {
            netDevicesCombo.getItems().addAll(String.format("#%d: [%s]", i++,
                    (device.getDescription() != null) ? device.getDescription() : device.getName()));
        }
        //selects first item in the combobox
        netDevicesCombo.getSelectionModel().selectFirst();
    }

    private void CaptureBtnNormalStyle() {
        CaptureBtn.setText("Start Capturing");
        CaptureBtn.setStyle("-fx-background-color: rgba(0, 0, 0, 0.2);");
    }

    private void CaptureBtnCapturingStyle() {
        CaptureBtn.setText("Stop Capturing");
        CaptureBtn.setStyle("-fx-background-color: rgba(0, 255, 0, 0.2);");
    }

    private void startCapturing() {
        frameNo = 1;
        allPackets.clear();
        PacketsListView.getItems().clear();
        PacketInfoTextArea.setText("");

        //Starts a new thread that captures packets and add them
        new Thread(() -> {
            while (Capturing)
                addNextPacket();
        }).start();
    }

    //Capture Btn Handler
    public void CaptureBtnClick() {
        if (Capturing) {
            //Stop capturing
            Capturing = false; //This will finish the thread that was created in "startCapturing()"
            pcap.breakloop();
            pcap.close();
            CaptureBtnNormalStyle();
        } else {
            //Start capturing
            CaptureBtnCapturingStyle();
            Capturing = true;
            startCapturing();
        }
    }

    public void ListViewClicked() {
        try { //Shows the selected packet (from the listview) info in the text area
            PacketInfoTextArea.setText(allPackets.get(PacketsListView.getSelectionModel().getSelectedIndex()));
        } catch (Exception e) {
        }
    }

    private void addNextPacket() {
        // Create a stream to hold the output
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        // IMPORTANT: Save the old System.out!
        PrintStream old = System.out; /////////////////////////////
        // Tell Java to use your special stream
        System.setOut(ps);

        PcapIf device = null;
        try {
            device = alldevs.get(netDevicesCombo.getSelectionModel().getSelectedIndex());
        } catch (Exception e) {
            return;
        }
        int snaplen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis

        pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null)
            return;

        pcap.loop(1, new PacketHandler(), "jNetPcap");
        //Because some frames can still show after clicking stop capturing
        //When stop capturing is clicked, next line will instantly fire
        if (!Capturing)
            return;

        // Put things back
        System.out.flush();
        System.setOut(old);
        // Show what happened
        //System.out.println("frameNo: " + frameNo + baos.toString());

        //Add captured packet info in both the ListView and the array of strings (allPackets)
        Platform.runLater(() -> PacketsListView.getItems().add("Frame #" + frameNo++ + " " + Parser.PrintInfo()));
        allPackets.add(baos.toString());
    }

    //triggers when pcapSaveBtn is clicked
    public void pcapSaveBtnClicked() {

    }

    //triggers when filterTxtField is clicked
    public void filterTxtFieldClicked() {

    }
}
