package com.customs;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;

/**
 * Главный класс приложения для Swing UI.
 * Ответственность: создание и управление графическим интерфейсом.
 */
public class Main {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(Main::createAndShowGUI);
    }

    /**
     * Создает и отображает графический интерфейс пользователя.
     */
    private static void createAndShowGUI() {
        JFrame frame = new JFrame("XML Signature Validator");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(800, 600);

        JTextArea xmlInput = new JTextArea();
        xmlInput.setLineWrap(true);
        xmlInput.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(xmlInput);

        JButton chooseCertButton = new JButton("Choose Public Key File (PEM)");
        JTextField certPathField = new JTextField();
        certPathField.setEditable(false);

        JButton validateButton = new JButton("Validate Signature");
        JTextArea resultArea = new JTextArea();
        resultArea.setEditable(false);

        chooseCertButton.addActionListener((ActionEvent e) -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Select Public Key PEM file");
            if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                File certFile = fileChooser.getSelectedFile();
                certPathField.setText(certFile.getAbsolutePath());
            }
        });

        validateButton.addActionListener((ActionEvent e) -> {
            try {
                String fullSoapXml = xmlInput.getText();

                if (certPathField.getText().isEmpty()) {
                    throw new IllegalArgumentException("Please choose a public key PEM file.");
                }
                File publicKeyFile = new File(certPathField.getText());

                // Извлечение подписи из XML и валидация
                String signatureBase64 = XmlSignatureProcessor.extractSignatureBase64(fullSoapXml);
                boolean isValid = XmlSignatureProcessor.verifySignature(fullSoapXml, signatureBase64, publicKeyFile);

                resultArea.setText("Signature is valid: " + isValid);
                resultArea.setBackground(isValid ? new Color(144, 238, 144) : new Color(255, 182, 193)); // LightGreen/Pink
            } catch (Exception ex) {
                resultArea.setText("Error: " + ex.getMessage());
                resultArea.setBackground(Color.RED);
                ex.printStackTrace();
            }
        });

        JPanel topPanel = new JPanel(new BorderLayout(5, 5));
        topPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        topPanel.add(chooseCertButton, BorderLayout.WEST);
        topPanel.add(certPathField, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(validateButton);

        frame.getContentPane().setLayout(new BorderLayout(10, 10));
        frame.getContentPane().add(topPanel, BorderLayout.NORTH);
        frame.getContentPane().add(scrollPane, BorderLayout.CENTER);
        frame.getContentPane().add(buttonPanel, BorderLayout.SOUTH);
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, scrollPane, new JScrollPane(resultArea));
        splitPane.setResizeWeight(0.7);
        frame.getContentPane().add(splitPane, BorderLayout.CENTER);


        frame.setVisible(true);
    }
}
