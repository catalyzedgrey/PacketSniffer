package src;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import jdk.internal.org.objectweb.asm.tree.FrameNode;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;

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

    private Boolean Capturing = false;
    private Thread captureThread;

    private ArrayList<String> allPackets;

    private int frameNo = 1;

    public void initialize() {
        initNetworks();
        allPackets = new ArrayList<>();
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
            netDevicesCombo.getItems().addAll(String.format("#%d: [%s]", i++, (device.getDescription() != null) ? device.getDescription()
                    : device.getName()));
        }
        netDevicesCombo.getSelectionModel().selectFirst();
    }

    public void CaptureBtnClick() {
        if (Capturing) {
            Capturing = false;
            CaptureBtn.setText("Start Capturing");
        } else {
            Capturing = true;
            CaptureBtn.setText("Stop Capturing");
            resetCapturing();
            captureThread = new Thread(this::CaptureControl);
            captureThread.start();
        }
    }

    private void resetCapturing() {
        frameNo = 0;
        allPackets.clear();
    }

    private void CaptureControl() {
        while (Capturing)
            capture();
    }

    public void ListViewClicked() {
        try {
            PacketInfoTextArea.setText(allPackets.get(PacketsListView.getSelectionModel().getSelectedIndex()));
        } catch (Exception e) {
        }
    }

    private void capture() {
        // Create a stream to hold the output
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        // IMPORTANT: Save the old System.out!
        PrintStream old = System.out;
        // Tell Java to use your special stream
        System.setOut(ps);

        PcapIf device = null;
        try {
            device = alldevs.get(netDevicesCombo.getSelectionModel().getSelectedIndex());
        } catch (Exception e) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("ERROR");
            alert.setContentText("You have not chosen a network device!");
            alert.showAndWait();
            return;
        }

        int snaplen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("ERROR");
            alert.setContentText("Error while opening device for capture: "
                    + errbuf.toString());
            alert.showAndWait();
            return;
        }

        final int[] j = {0};
        PcapPacketHandler<String> jpacketHandler = (packet, user) -> {
            Ip4 ip = new Ip4();
            if (!packet.hasHeader(ip)) {
                return; // Not IP packet
            }
            System.out.println(packet);
        };
        pcap.loop(1, jpacketHandler, "jNetPcap");
        pcap.close();

        // Put things back
        System.out.flush();
        System.setOut(old);
        // Show what happened
        System.out.println("frameNo: " + frameNo + baos.toString());

        Platform.runLater(() -> PacketsListView.getItems().add("Frame #" + frameNo++));
        allPackets.add(baos.toString());
    }
}
