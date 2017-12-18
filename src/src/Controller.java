package src;

import javafx.beans.property.BooleanProperty;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
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
    enum Connection {UDP, TCP}

    @FXML
    private ComboBox netDevicesCombo;
    @FXML
    private Button CaptureBtn;
    @FXML
    public ListView<String> PacketsListView;
    @FXML
    public TextField filterTxtField;
    @FXML
    private TreeView<String> PacketInfoTreeView;

    private Boolean expandedNodes[] = new Boolean[5];

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
        for (int i = 0; i < 5; i++)
            expandedNodes[i] = false;

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
        PacketInfoTreeView.setRoot(null);
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
                splitPacketInfo(allPackets.get(index).toString());
            } catch (Exception e) {
            }
        else
            PacketInfoTreeView.setRoot(null);
    }

    private void splitPacketInfo(String allInfo) {

        // System.out.println(allInfo);
        boolean nearEnd = false;

        TreeItem<String> dummyRoot = new TreeItem<>();
        PacketInfoTreeView.setRoot(dummyRoot);
        PacketInfoTreeView.setShowRoot(false);

        ArrayList<TreeItem> allTreeItems = new ArrayList<>();

        TreeItem<String> frameRoot = new TreeItem<>("Frame");
        TreeItem<String> ethernetRoot = new TreeItem<>(netDevicesCombo.getValue().toString());
        TreeItem<String> ipRoot = new TreeItem<>("IP");
        TreeItem<String> tcpRoot = new TreeItem<>("TCP");
        TreeItem<String> udpRoot = new TreeItem<>("Udp");
        TreeItem<String> dataRoot = new TreeItem<>("Data");

        allTreeItems.add(frameRoot);
        allTreeItems.add(ethernetRoot);
        allTreeItems.add(ipRoot);
        allTreeItems.add(tcpRoot);
        allTreeItems.add(udpRoot);
        allTreeItems.add(dataRoot);

        for (TreeItem ti : allTreeItems) {
            ti.expandedProperty().addListener((observable, oldValue, newValue) -> {
                try {
                    expandedNodes[allTreeItems.indexOf(ti)] = newValue;
                } catch (Exception e) {
                }
            });
        }

        String[] splitParts = allInfo.split("\\n");

        Connection connection = null;

        for (int i = 0; i < splitParts.length; i++) {
            if (splitParts[i].startsWith("Frame:")) {
                splitParts[i] = splitParts[i].replaceAll("Frame:", "");
                splitParts[i] = splitParts[i].trim().replaceAll(" +", " ");
                // System.out.println(splitParts[i]);
                if (!splitParts[i].equals("")) {
                    TreeItem<String> leaf = new TreeItem<String>(splitParts[i]);
                    frameRoot.getChildren().add(leaf);
                }
            }
            if (splitParts[i].startsWith("Eth:")) {
                splitParts[i] = splitParts[i].replaceAll("Eth:", "");
                splitParts[i] = splitParts[i].replaceAll("Ethernet", "");
                splitParts[i] = splitParts[i].replaceAll("\\*\\*\\*\\*\\*\\*\\*", "");
                String str = " - \"";
                String str2 = "\" -";
                splitParts[i] = splitParts[i].replaceAll(str, "");
                splitParts[i] = splitParts[i].replaceAll(str2, "");
                splitParts[i] = splitParts[i].trim().replaceAll(" +", " ");
                // System.out.println(splitParts[i]);
                if (!splitParts[i].equals("")) {
                    TreeItem<String> leaf = new TreeItem<String>(splitParts[i]);
                    ethernetRoot.getChildren().add(leaf);
                }
            }
            if (splitParts[i].startsWith("Ip:") | splitParts[i].startsWith("Ip6:") | splitParts[i].startsWith("Ip4:")) {
                splitParts[i] = splitParts[i].replaceAll("Ip: | (Ip6: \\*\\*\\*\\*\\*\\*\\*)| (Ip4: \\*\\*\\*\\*\\*\\*\\*)", "");
                String str = " - \"";
                String str2 = "\" -";
                splitParts[i] = splitParts[i].replaceAll(str, "");
                splitParts[i] = splitParts[i].replaceAll(str2, "");
                splitParts[i] = splitParts[i].trim().replaceAll(" +", " ");
                //   System.out.println(splitParts[i]);
                if (!splitParts[i].equals("")) {
                    TreeItem<String> leaf = new TreeItem<String>(splitParts[i]);
                    ipRoot.getChildren().add(leaf);
                }
            }
            if (splitParts[i].startsWith("Tcp:")) {
                connection = Controller.Connection.TCP;
                splitParts[i] = splitParts[i].replaceAll("Tcp: | (Tcp: \\*\\*\\*\\*\\*\\*\\*)| (Ip4: \\*\\*\\*\\*\\*\\*\\*)", "");
                String str = " - \"";
                String str2 = "\" -";
                splitParts[i] = splitParts[i].replaceAll(str, "");
                splitParts[i] = splitParts[i].replaceAll(str2, "");
                splitParts[i] = splitParts[i].trim().replaceAll(" +", " ");
                //  System.out.println(splitParts[i]);
                if (!splitParts[i].equals("")) {
                    TreeItem<String> leaf = new TreeItem<String>(splitParts[i]);
                    tcpRoot.getChildren().add(leaf);
                }
            }
            if (splitParts[i].startsWith("Udp:")) {
                connection = Controller.Connection.UDP;
                splitParts[i] = splitParts[i].replaceAll("Udp: | (Udp: \\*\\*\\*\\*\\*\\*\\*)", "");
                String str = " - \"";
                String str2 = "\" -";
                splitParts[i] = splitParts[i].replaceAll(str, "");
                splitParts[i] = splitParts[i].replaceAll(str2, "");
                splitParts[i] = splitParts[i].trim().replaceAll(" +", " ");
                //  System.out.println(splitParts[i]);
                if (!splitParts[i].equals("")) {
                    TreeItem<String> leaf = new TreeItem<String>(splitParts[i]);
                    udpRoot.getChildren().add(leaf);
                }
            }
            if (splitParts[i].startsWith("Data:") || nearEnd) {
                nearEnd = true;
                splitParts[i] = splitParts[i].replaceAll("Data: | (Data: \\*\\*\\*\\*\\*\\*\\*)", "");
                String str = " - \"";
                String str2 = "\" -";
                splitParts[i] = splitParts[i].replaceAll(str, "");
                splitParts[i] = splitParts[i].replaceAll(str2, "");
                //  System.out.println(splitParts[i]);
                if (!splitParts[i].equals("")) {
                    TreeItem<String> leaf = new TreeItem<String>(splitParts[i]);
                    dataRoot.getChildren().add(leaf);
                }
            }
            if (i == splitParts.length - 1) {
                dummyRoot.getChildren().add(frameRoot);
                dummyRoot.getChildren().add(ethernetRoot);
                dummyRoot.getChildren().add(ipRoot);
                if (connection == Connection.TCP) {
                    dummyRoot.getChildren().add(tcpRoot);
                }
                if (connection == Connection.UDP) {
                    dummyRoot.getChildren().add(udpRoot);
                }
                dummyRoot.getChildren().add(dataRoot);
            }
        }

        if (expandedNodes[0])
            frameRoot.setExpanded(true);
        if (expandedNodes[1])
            ethernetRoot.setExpanded(true);
        if (expandedNodes[2])
            ipRoot.setExpanded(true);
        if (expandedNodes[3]) {
            tcpRoot.setExpanded(true);
            udpRoot.setExpanded(true);
        }
        if (expandedNodes[4])
            dataRoot.setExpanded(true);
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
