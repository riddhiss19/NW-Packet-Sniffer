import org.pcap4j.core.*;
import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;

import static java.lang.System.exit;

public class GUI extends Thread implements ActionListener {
    static Color buttonColor = new Color(247, 229, 233);
    static int totalPackets = 1000000;
    static PcapPacket[] packetList = new PcapPacket[totalPackets];
    static boolean capture = true;
    static boolean filterNotEnabled = true;
    static Thread startTemp = null;
    static String[] col = { "S.No", "Time", "Source", "Destination", "Protocol", "Length" };
    static String[] filterOptions = { "S.No", "Time", "Source", "Destination", "Protocol", "Length" };
    static int sno = 0;
    static String[][] data = new String[totalPackets][6];
    static PcapNetworkInterface selectedNIC = null;
    static PcapHandle handle = null;
    static JFrame frame;
    static JLabel interfaceLabel;
    static JComboBox<String> interfaceChoice;
    static JButton start;
    static JButton stop;
    static JButton save;
    static JLabel filterL;
    static JComboBox<String> filterSelect;
    static JTextField filterText;
    static JButton filter;
    static JTable table;
    static JScrollPane scrollPane;
    static JTextArea details;
    static JTextArea dataField;
    static JScrollPane scrollData;
    static JScrollPane scrollDetails;
    static JFileChooser fileChooser;
    static JButton analysis;
    static JButton threshold;

    @Override
    public void run() {
        if (Thread.currentThread().getName().equals("thread-start")) {
            capture = true;
            // System.out.println(interfaceChoice);
            String s = (String) interfaceChoice.getSelectedItem();
            try {
                selectedNIC = NIC.getSelectedNIC(NIC.getNIC(), s);
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
            if (selectedNIC == null) {
                System.out.println("NO NIC Selected");
                exit(1);
            }
            int snapshotLength = 65536; // in bytes
            int readTimeout = 50; // in milliseconds
            try {
                handle = selectedNIC.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                        readTimeout);
            } catch (PcapNativeException ex) {
                throw new RuntimeException(ex);
            }

            // Creating a listener to define what to do with the received packets
            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(PcapPacket packet) {
                    // Overriding the default gotPacket() function
                    if (capture && (filterNotEnabled || PacketDetails.isFilterTrue(packet))) {
                        packetList[sno] = packet;
                        String time = packet.getTimestamp().toString();
                        String source = PacketDetails.getSource(packet);
                        String des = PacketDetails.getDestination(packet);
                        String protocol = PacketDetails.getProtocol(packet);
                        String length = PacketDetails.getLength(packet);
                        // System.out.println(packet);
                        data[sno][0] = Integer.toString(sno + 1);
                        data[sno][1] = time;
                        data[sno][2] = source;
                        data[sno][3] = des;
                        data[sno][4] = protocol;
                        data[sno][5] = length;
                        sno++;
                        table.repaint();
                        scrollPane.repaint();
                    }
                }
            };

            // telling the handle to loop using the listener we created
            try {
                int maxPackets = totalPackets;
                handle.loop(maxPackets, listener);
            } catch (InterruptedException | PcapNativeException | NotOpenException ex) {
                ex.printStackTrace();
            }
        }

        else if (Thread.currentThread().getName().equals("thread-stop")) {
            capture = false;
        } else if (Thread.currentThread().getName().equals("thread-filter")) {
            filterNotEnabled = false;
        } else if (Thread.currentThread().getName().equals("thread-save")) {
            if (handle == null)
                JOptionPane.showMessageDialog(frame, "No Packets! Choose a NIC and Capture", "Alert",
                        JOptionPane.WARNING_MESSAGE);
            else {
                int option = fileChooser.showDialog(frame, "Select File");
                if (option == JFileChooser.APPROVE_OPTION) {
                    String filePath = fileChooser.getSelectedFile().getAbsolutePath();
                    PcapDumper dumper;
                    try {
                        dumper = handle.dumpOpen(filePath);
                    } catch (PcapNativeException | NotOpenException e) {
                        throw new RuntimeException(e);
                    }
                    for (PcapPacket packet : packetList) {
                        try {
                            dumper.dump(packet, packet.getTimestamp());
                        } catch (NotOpenException e) {
                            e.printStackTrace();
                        }
                    }
                    try {
                        dumper.flush();
                    } catch (PcapNativeException | NotOpenException e) {
                        throw new RuntimeException(e);
                    }
                    dumper.close();
                }
            }
        } else if (Thread.currentThread().getName().equals("thread-analysis")) {
            JDialog plotDialog = new JDialog(frame, "Real Time Analysis Menu", true);
            plotDialog.setBounds(400, 200, 300, 140);
            JLabel plotLabel = new JLabel("Select: ");
            plotLabel.setBounds(10, 10, 50, 20);
            String[] plotOptions = { "Network Throughput", "Top Talkers", "Protocol Distribution" };
            JComboBox<String> plotSelection = new JComboBox<>(plotOptions);
            // description later
            plotSelection.setBounds(62, 10, 200, 20);
            JButton ok = new JButton("OK");
            ok.setBounds(130, 45, 60, 20);
            ok.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    plotDialog.dispose();
                    String selectedPlot = (String) plotSelection.getSelectedItem();
                    // System.out.println(selectedPlot);
                    assert selectedPlot != null;
                    RealTimeAnalysis.chartPlot(selectedPlot);
                }
            });
            plotDialog.add(plotLabel);
            plotDialog.add(plotSelection);
            plotDialog.add(ok);
            plotDialog.setLayout(null);
            plotDialog.setVisible(true);
        } else if (Thread.currentThread().getName().equals("thread-threshold")) {
            JDialog thresholdDialog = new JDialog(frame, "Set Threshold Values", true);
            thresholdDialog.setBounds(400, 200, 400, 150);
            JLabel thresholdValLabel = new JLabel("Set Max Number of Packets per IP: ");
            thresholdValLabel.setBounds(10, 10, 200, 20);
            JTextField thresholdVal = new JTextField();
            thresholdVal.setBounds(215, 10, 150, 20);
            JLabel thresholdPercentLabel = new JLabel("Set Max Percent of Packets per IP: ");
            thresholdPercentLabel.setBounds(10, 35, 200, 20);
            JTextField thresholdPercent = new JTextField();
            thresholdPercent.setBounds(215, 35, 150, 20);
            JButton ok = new JButton("OK");
            ok.setBounds(160, 70, 60, 20);
            ok.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    thresholdDialog.dispose();
                    int val = Integer.parseInt(thresholdVal.getText());
                    double percent = Double.parseDouble(thresholdPercent.getText());
                    RealTimeAnalysis.thresholdValue = val;
                    if (percent > 100) {
                        JOptionPane.showMessageDialog(thresholdDialog, "Percentage Should Be At Maximum 100", "Alert",
                                JOptionPane.WARNING_MESSAGE);
                    } else
                        RealTimeAnalysis.thresholdPercentage = percent;
                }
            });
            thresholdDialog.add(thresholdValLabel);
            thresholdDialog.add(thresholdVal);
            thresholdDialog.add(thresholdPercent);
            thresholdDialog.add(thresholdPercentLabel);
            thresholdDialog.add(ok);
            thresholdDialog.setLayout(null);
            thresholdDialog.setVisible(true);
        }
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == start) {
            GUI t1 = new GUI();
            t1.setName("thread-start");
            startTemp = t1;
            t1.start();
        } else if (e.getSource() == stop) {
            GUI t2 = new GUI();
            t2.setName("thread-stop");
            t2.start();
        } else if (e.getSource() == filter) {
            GUI t3 = new GUI();
            t3.setName("thread-filter");
            t3.start();
        } else if (e.getSource() == save) {
            GUI t4 = new GUI();
            t4.setName("thread-save");
            t4.start();
        } else if (e.getSource() == analysis) {
            GUI t5 = new GUI();
            t5.setName("thread-analysis");
            t5.start();
        } else if (e.getSource() == threshold) {
            GUI t6 = new GUI();
            t6.setName("thread-threshold");
            t6.start();
        }
    }

    public void gui() throws IOException {

        // creating components
        frame = new JFrame("Group 83: Multi-Protocol Packet Sniffer");

        frame.getContentPane().setBackground(new Color(196, 241, 239));
        frame.setBounds(50, 10, 1000, 700);
        interfaceLabel = new JLabel("Choose NIC:");
        interfaceLabel.setBounds(10, 10, 80, 20);
        String[] choices = NIC.getNICNames(NIC.getNIC());
        interfaceChoice = new JComboBox<>(choices);
        interfaceChoice.setBounds(113, 10, 300, 20);
        start = new JButton("Start");
        start.setBounds(425, 10, 70, 20);
        start.setBackground(buttonColor);
        stop = new JButton("Stop");
        stop.setBounds(510, 10, 70, 20);
        stop.setBackground(buttonColor);
        save = new JButton("Save");
        save.setBounds(595, 10, 70, 20);
        save.setBackground(buttonColor);
        filterL = new JLabel("Select Filter:");
        filterL.setBounds(10, 40, 80, 20);
        filterSelect = new JComboBox<>(filterOptions);
        filterSelect.setBounds(95, 40, 150, 20);
        filterText = new JTextField();
        filterText.setBounds(250, 40, 100, 20);
        filter = new JButton("Filter");
        filter.setBackground(buttonColor);
        filter.setBounds(355, 40, 80, 20);
        table = new JTable(data, col);
        table.setBackground(new Color(252, 251, 251));
        // Setting default column sizes
        int[] colSize = { 80, 190, 250, 250, 90, 90 };
        for (int i = 0; i < table.getColumnCount(); i++) {
            TableColumn column = table.getColumnModel().getColumn(i);
            column.setPreferredWidth(colSize[i]);
        }
        scrollPane = new JScrollPane(table);
        scrollPane.setBounds(10, 70, frame.getWidth() - 35, 200);
        details = new JTextArea();
        scrollDetails = new JScrollPane(details);
        scrollDetails.setSize(MIN_PRIORITY, MAX_PRIORITY);
        scrollDetails.setBounds(10, 300, frame.getWidth() - 35, 150);
        dataField = new JTextArea();
        dataField.setLineWrap(true);
        scrollData = new JScrollPane(dataField);
        scrollData.setBounds(10, 465, frame.getWidth() - 35, 150);
        fileChooser = new JFileChooser();
        analysis = new JButton("Real Time Analysis");
        analysis.setBounds(750, 10, 140, 20);
        analysis.setBackground(buttonColor);
        threshold = new JButton("Set Threshold");
        threshold.setBounds(160, 625, 120, 20);
        threshold.setBackground(buttonColor);
        // adding components to frame

        frame.add(interfaceLabel);
        frame.add(interfaceChoice);
        frame.add(start);
        frame.add(stop);
        frame.add(save);
        frame.add(filterL);
        frame.add(filterText);
        frame.add(filterSelect);
        frame.add(filter);
        frame.add(scrollPane);
        frame.add(scrollData);
        frame.add(scrollDetails);
        frame.add(analysis);
        // frame.add(threshold);

        // adding action listeners
        start.addActionListener(this);
        stop.addActionListener(this);
        save.addActionListener(this);
        filter.addActionListener(this);
        analysis.addActionListener(this);
        // threshold.addActionListener(this);

        // frame properties
        frame.setLayout(null);
        frame.setResizable(false);
        frame.setVisible(true);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        // adding event handling for table
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ListSelectionModel model = table.getSelectionModel();
        model.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                int rowIndex = table.getSelectedRow();
                if (!e.getValueIsAdjusting() && rowIndex != -1) {
                    if (packetList[rowIndex] != null) {
                        PacketDetails.setDataField(packetList[rowIndex]);
                        PacketDetails.setDetails(packetList[rowIndex]);
                    }
                }
            }
        });
    }
}
