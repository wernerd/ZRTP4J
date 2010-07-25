package demo;

import java.awt.Container;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemListener;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.border.EtchedBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import javax.swing.event.*;

import java.awt.event.ItemEvent;

import gnu.java.zrtp.ZrtpConstants;
import gnu.java.zrtp.ZrtpConfigure;

public class ConfigureDemo extends JFrame {

    private ZrtpConfigure active = new ZrtpConfigure();

    private ZrtpConfigure inActive = new ZrtpConfigure();

    PublicKeyControls pkc = new PublicKeyControls();
    HashControls hc = new HashControls();
    CipherControls cc = new CipherControls();
    SasControls sc = new SasControls();
    LengthControls lc = new LengthControls();
    
    public ConfigureDemo() {

        setTitle("ZRTP Configure demo");

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        
        JPanel panel = new JPanel();

        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        panel.setLayout(new GridLayout(5, 1));

        final JButton stdButton = new JButton("Standard");
        stdButton.setOpaque(false);
        stdButton.setSize(15, 15);

        final JButton mandButton = new JButton("Mandatory");
        mandButton.setOpaque(false);
        mandButton.setSize(15, 15);

        // key = "impl.media.configform.DOWN";
        final JButton saveButton = new JButton("Save");
        // downButton.setMnemonic(resources.getI18nMnemonic(key));
        saveButton.setOpaque(false);
        saveButton.setSize(15, 15);

        JPanel buttonBar = new JPanel(new GridLayout(1, 4));
        buttonBar.add(stdButton);
        buttonBar.add(mandButton);
        buttonBar.add(Box.createHorizontalStrut(10));
        buttonBar.add(saveButton);
        mainPanel.add(buttonBar);
        mainPanel.add(Box.createVerticalStrut(7));

        JPanel checkBar = new JPanel(new GridLayout(1,2));
        final JCheckBox trustedMitM = new JCheckBox("Trusted MitM", false);
        final JCheckBox sasSignature = new JCheckBox("SAS signature processing", false);
        checkBar.add(trustedMitM);
        checkBar.add(sasSignature);
        mainPanel.add(checkBar);
        mainPanel.add(Box.createVerticalStrut(7));
        
        ActionListener buttonListener = new ActionListener() {

            public void actionPerformed(ActionEvent event) {
                Object source = event.getSource();
                if (source == stdButton) {
                    inActive.clear();
                    active.setStandardConfig();
                    pkc.setStandard();
                    hc.setStandard();
                    sc.setStandard();
                    cc.setStandard();
                    lc.setStandard();
                }
                else if (source == mandButton) {
                    inActive.clear();
                    active.setMandatoryOnly();
                    pkc.setStandard();
                    hc.setStandard();
                    sc.setStandard();
                    cc.setStandard();
                    lc.setStandard();
                }
                else if (source == saveButton)
                    ;
                else
                    return;

            }
        };
        stdButton.addActionListener(buttonListener);
        mandButton.addActionListener(buttonListener);
        saveButton.addActionListener(buttonListener);

        ItemListener itemListener = new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                Object source = e.getItemSelectable();

                if (source == trustedMitM) {
                     active.setTrustedMitM(trustedMitM.isSelected());
                } else if (source == sasSignature) {
                    active.setSasSignature(sasSignature.isSelected());
                }
            }
        };
        trustedMitM.addItemListener(itemListener);
        sasSignature.addItemListener(itemListener);
        
        panel.add(pkc);
        panel.add(hc);
        panel.add(cc);
        panel.add(sc);
        panel.add(lc);
        mainPanel.add(panel);
        add(mainPanel);

        setSize(panel.getPreferredSize());

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setVisible(true);

    }

    class PublicKeyControls extends JPanel {

        private final ZrtpConfigureTableModel<ZrtpConstants.SupportedPubKeys> dataModel;
        
        PublicKeyControls() {
            dataModel = new ZrtpConfigureTableModel<ZrtpConstants.SupportedPubKeys>(
                    ZrtpConstants.SupportedPubKeys.DH2K, active, inActive, "DH3K;MULT;");
            createControls(this, dataModel, "Public key algorithms");
        }
        
        void setStandard() {
            dataModel.setStandardConfig();
        }
    }

    class HashControls extends JPanel {

        private final ZrtpConfigureTableModel<ZrtpConstants.SupportedHashes> dataModel;
        
        HashControls() {
            dataModel = new ZrtpConfigureTableModel<ZrtpConstants.SupportedHashes>(
                    ZrtpConstants.SupportedHashes.S256, active, inActive, "S256");
            createControls(this, dataModel, "Hash algorithms");
        }

        void setStandard() {
            dataModel.setStandardConfig();
        }
}

    class CipherControls extends JPanel {

        private final ZrtpConfigureTableModel<ZrtpConstants.SupportedSymCiphers> dataModel;
        
        CipherControls() {
            dataModel = new ZrtpConfigureTableModel<ZrtpConstants.SupportedSymCiphers>(
                    ZrtpConstants.SupportedSymCiphers.AES1, active, inActive, "AES1");
            createControls(this, dataModel, "Symmetric cipher algorithms");
        }

        void setStandard() {
            dataModel.setStandardConfig();
        }
}

    class SasControls extends JPanel {
        
        private final ZrtpConfigureTableModel<ZrtpConstants.SupportedSASTypes> dataModel;
        
        SasControls() {
            dataModel = new ZrtpConfigureTableModel<ZrtpConstants.SupportedSASTypes>(
                    ZrtpConstants.SupportedSASTypes.B32, active, inActive, "B32");
            createControls(this, dataModel, "SAS types");
        }

        void setStandard() {
            dataModel.setStandardConfig();
        }
}

    class LengthControls extends JPanel {

        private final ZrtpConfigureTableModel<ZrtpConstants.SupportedAuthLengths> dataModel;
        
        LengthControls() {
            dataModel = new ZrtpConfigureTableModel<ZrtpConstants.SupportedAuthLengths>(
                    ZrtpConstants.SupportedAuthLengths.HS32, active, inActive, "HS32;HS80");
            createControls(this, dataModel, "SRTP authentication length");
        }

        void setStandard() {
            dataModel.setStandardConfig();
        }
}

    private <T extends Enum<T>> void createControls(JPanel panel,
            ZrtpConfigureTableModel<T> model, String title) {

        final JButton upButton = new JButton("Up");
        upButton.setOpaque(false);

        // key = "impl.media.configform.DOWN";
        final JButton downButton = new JButton("Down");
        // downButton.setMnemonic(resources.getI18nMnemonic(key));
        downButton.setOpaque(false);

        Container buttonBar = new JPanel(new GridLayout(0, 1));
        buttonBar.add(upButton);
        buttonBar.add(downButton);

        panel.setLayout(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(BorderFactory
                .createEtchedBorder(EtchedBorder.LOWERED), title));

        final JTable table = new JTable(model.getRowCount(), 2);
        table.setShowGrid(false);
        table.setTableHeader(null);
        table.setModel(model);
        table.setPreferredScrollableViewportSize(new Dimension(400, 65));
        //table.setFillsViewportHeight(true); // Since 1.6

        /*
         * The first column contains the check boxes which enable/disable their
         * associated encodings and it doesn't make sense to make it wider than
         * the check boxes.
         */
        TableColumnModel tableColumnModel = table.getColumnModel();
        TableColumn tableColumn = tableColumnModel.getColumn(0);
        tableColumn.setMaxWidth(tableColumn.getMinWidth() + 5);
        table.doLayout();
        
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.CENTER;
        constraints.fill = GridBagConstraints.BOTH;
        constraints.gridwidth = 1;
        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.weightx = 1;
        constraints.weighty = 1;
        panel.add(new JScrollPane(table), constraints);

        constraints.anchor = GridBagConstraints.NORTHEAST;
        constraints.fill = GridBagConstraints.NONE;
        constraints.gridwidth = 1;
        constraints.gridx = 1;
        constraints.gridy = 1;
        constraints.weightx = 0;
        constraints.weighty = 0;
        panel.add(buttonBar, constraints);

        ListSelectionListener tableSelectionListener = new ListSelectionListener() {
            @SuppressWarnings("unchecked")
            public void valueChanged(ListSelectionEvent event) {
                if (table.getSelectedRowCount() == 1) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow > -1) {
                        ZrtpConfigureTableModel<T> model = (ZrtpConfigureTableModel<T>) table
                                .getModel();
                        upButton.setEnabled(selectedRow > 0
                                && model.checkEnableUp(selectedRow));
                        downButton.setEnabled(selectedRow < (table
                                .getRowCount() - 1)
                                && model.checkEnableDown(selectedRow));
                        return;
                    }
                }
                upButton.setEnabled(false);
                downButton.setEnabled(false);
            }
        };
        table.getSelectionModel().addListSelectionListener(
                tableSelectionListener);

        TableModelListener tableListener = new TableModelListener() {
            @SuppressWarnings("unchecked")
            public void tableChanged(TableModelEvent e) {
                if (table.getSelectedRowCount() == 1) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow > -1) {
                        ZrtpConfigureTableModel<T> model = (ZrtpConfigureTableModel<T>) table
                                .getModel();
                        upButton.setEnabled(selectedRow > 0
                                && model.checkEnableUp(selectedRow));
                        downButton.setEnabled(selectedRow < (table
                                .getRowCount() - 1)
                                && model.checkEnableDown(selectedRow));
                        return;
                    }
                }
                upButton.setEnabled(false);
                downButton.setEnabled(false);
            }
        };
        table.getModel().addTableModelListener(tableListener);

        tableSelectionListener.valueChanged(null);

        ActionListener buttonListener = new ActionListener() {
            @SuppressWarnings("unchecked")
            public void actionPerformed(ActionEvent event) {
                Object source = event.getSource();
                boolean up;
                if (source == upButton)
                    up = true;
                else if (source == downButton)
                    up = false;
                else
                    return;

                int index = ((ZrtpConfigureTableModel<T>) table.getModel())
                        .move(table.getSelectedRow(), up, up);
                table.getSelectionModel().setSelectionInterval(index, index);
            }
        };
        upButton.addActionListener(buttonListener);
        downButton.addActionListener(buttonListener);
    }

    public static void main(String[] args) {
        new ConfigureDemo();
    }

}
