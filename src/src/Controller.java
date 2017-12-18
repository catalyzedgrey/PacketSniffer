package src;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import org.jnetpcap.*;
import org.jnetpcap.packet.PcapPacket;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class Controller {
    @FXML
    private ComboBox netDevicesCombo;
    @FXML
    private Button CaptureBtn;
    @FXML
    private Button pcapLoadBtn;
    @FXML
    private TextArea PacketInfoTextArea;
    @FXML
    public ListView<String> PacketsListView;
    @FXML
    public TextField filterTxtField;

    private List<PcapIf> alldevs;
    private StringBuilder errbuf;

    private Boolean Capturing;
    public int frameNo;

    public ArrayList<PcapPacket> allPackets;
    public ObservableList<String> observablePackets;
    private FilteredList<String> filterItems;

    private PacketHandler pHandler;
    private Pcap pcap;
    private int snaplen = 64 * 1024; // Capture all packets, no trucation
    private int flags = Pcap.MODE_PROMISCUOUS;
    private int timeout = 10 * 1000; // 10 seconds in millis
    final int dlt = PcapDLT.EN10MB.value;


    public void initialize() {
        allPackets = new ArrayList<>();
        observablePackets = FXCollections.observableArrayList();
        filterItems = new FilteredList<>(observablePackets);

        pHandler = new PacketHandler(this);
        PacketsListView.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);

        PacketsListView.setItems(filterItems); // bind predicate to text filterTxtField
        filterItems.predicateProperty().bind(javafx.beans.binding.Bindings.createObjectBinding(() -> {
            String text = filterTxtField.getText();
            if (text == null || text.isEmpty()) {
                return null;
            } else {
                final String uppercase = text.toUpperCase();
                return (String) -> String.toUpperCase().contains(uppercase);
            }
        }, filterTxtField.textProperty()));

        initNetworkDevices();

        Capturing = false;
        //CaptureBtnClick();
    }

    private void initNetworkDevices() {
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

    private void clearPackets() {
        frameNo = 1;
        allPackets.clear();
        observablePackets.clear();
        filterItems.clear();
        PacketsListView.getItems().clear();
        PacketInfoTextArea.setText("");
    }

    private void startCapturing() {
        clearPackets();

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
        //Shows info only if selecting one packet
        if (PacketsListView.getSelectionModel().getSelectedItems().size() == 1)
            try { //Shows the selected packet (from the listview) info in the text area
                String s = PacketsListView.getSelectionModel().getSelectedItem();
                int index = Integer.parseInt(s.substring(1, s.indexOf(" "))) - 1;
                PacketInfoTextArea.setText(allPackets.get(index).toString());
            } catch (Exception e) {
            }
        else
            PacketInfoTextArea.setText("");
    }

    private void addNextPacket() {
        try {
            PcapIf device = alldevs.get(netDevicesCombo.getSelectionModel().getSelectedIndex());
            pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
            pcap.loop(1, pHandler, "jNetPcap");
        } catch (Exception e) {
        }
    }

    //triggers when pcapSaveBtn is clicked
    public void pcapSaveBtnClicked() {
        //get all selected indices from the listview
        ObservableList<Integer> selectedIndices = PacketsListView.getSelectionModel().getSelectedIndices();
        if (selectedIndices.size() == 0) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Error");
            alert.setHeaderText("No packets are selected!");
            alert.showAndWait();
            return;
        }

        final PcapDumper dumper;
        //creating a file
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save path");
        //Set extension filter
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("pcap files (*.pcap)", "*.pcap"));
        fileChooser.setInitialFileName("Packets");
        File file = fileChooser.showSaveDialog(Main.stage);
        if (file == null) //User pressed cancel
            return;

        final Pcap pcapDead = Pcap.openDead(dlt, snaplen);
        dumper = pcapDead.dumpOpen(file.getAbsolutePath()); //calling pcap dumper to open the created file
        for (String s : PacketsListView.getSelectionModel().getSelectedItems()) {
            int index = Integer.parseInt(s.substring(1, s.indexOf(" "))) - 1;
            final PcapPacket packet = allPackets.get(index);
            //System.out.println(s);
            //System.out.println(packet);
            //giving your packet a header
            final PcapHeader h = new PcapHeader(packet.size(), packet.size());
            dumper.dump(h, packet); //save num packets with the initialized header
        }
        dumper.close();
        pcapDead.close();
    }

    public void pcapLoadBtnClicked() {

        if (Capturing) {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Error");
            alert.setHeaderText("Please stop capturing first.");
            alert.showAndWait();
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Pcap path");
        //Set extension filter
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("pcap files (*.pcap)", "*.pcap"));
        File file = fileChooser.showOpenDialog(Main.stage);

        if (file == null) //User pressed cancel
            return;

        //clears only when user chooses a file
        clearPackets();

        Pcap pcapOff = Pcap.openOffline(file.getAbsolutePath(), errbuf);
        //max saved packet load 1000 packet
        pcapOff.loop(1000, pHandler, "jNetPcap");
        pcapOff.close();
    }
}
