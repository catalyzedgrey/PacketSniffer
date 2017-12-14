package src;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import org.jnetpcap.*;
import org.jnetpcap.packet.PcapPacket;

import java.util.ArrayList;
import java.util.List;

public class Controller {
    @FXML
    private ComboBox netDevicesCombo;
    @FXML
    private Button CaptureBtn;
    @FXML
    private TextArea PacketInfoTextArea;
    @FXML
    public ListView PacketsListView;
    @FXML
    private TextField filterTxtField;

    private List<PcapIf> alldevs;
    private StringBuilder errbuf;

    private Boolean Capturing = false;
    public int frameNo;

    public ArrayList<PcapPacket> allPackets;

    private PacketHandler pHandler;
    private Pcap pcap;
    private int snaplen = 64 * 1024; // Capture all packets, no trucation
    private int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
    private int timeout = 10 * 1000; // 10 seconds in millis
    final int dlt = PcapDLT.EN10MB.value;


    public void initialize() {
        CaptureBtnNormalStyle();
        allPackets = new ArrayList<>();
        pHandler = new PacketHandler(this);
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
            PacketInfoTextArea.setText(allPackets.get(PacketsListView.getSelectionModel().getSelectedIndex()).toString());
        } catch (Exception e) {
        }
    }

    private void addNextPacket() {
        try {
            PcapIf device = alldevs.get(netDevicesCombo.getSelectionModel().getSelectedIndex());
            pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
            pcap.loop(1, pHandler, "jNetPcap");
        } catch (Exception e) {
            return;
        }
    }

    //triggers when pcapSaveBtn is clicked
    public void pcapSaveBtnClicked() {
        final Pcap pcap = Pcap.openDead(dlt, snaplen);

        PcapPacket packet = allPackets.get(PacketsListView.getSelectionModel().getSelectedIndex());

        //giving your packet a header; which will be passed to the dumper method later
        final PcapHeader h = new PcapHeader(packet.size(), packet.size());
        //creating a file
        //SHOULD NOT OVERWRITE FILE //IMPLEMENT LATER ///////////////////////////////////////////////////////////////////////////
        final String saved_packets = "savedPacket.pcap";
        final PcapDumper dumper = pcap.dumpOpen(saved_packets); //calling pcap dumper to open the created file
        dumper.dump(h, packet); //save num packets with the initialized header
        dumper.close();
        pcap.close();
    }

    //triggers when filterTxtField is clicked
    public void filterTxtFieldClicked() {

    }
}
