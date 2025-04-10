package org.example.plecak;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class AppController {

    @FXML
    private Button KeyGeneratorButton;

    @FXML
    private Button  LoadKeyButton;

    @FXML
    private Button  SaveKeyButton;

    @FXML
    private Button encryptButton;

    @FXML
    private Button decryptButton;

    @FXML
    private Button LoadNormalText;

    @FXML
    private Button  SaveNormalText;

    @FXML
    private Button LoadEncryptedText;

    @FXML
    private Button  SaveEncryptedText;

    @FXML
    private TextField FirstKey;

    @FXML
    private TextField SecondKey;

    @FXML
    private TextArea NormalTextArea;

    @FXML
    private TextArea EncryptTextArea;

    @FXML
    private CheckBox FileCheckBox;

    private String K1, K2;

    private Plecak plecak = new Plecak();

    private BigInteger[] encodedBytes = new BigInteger[]{};  // Zmieniamy typ na BigInteger[]
    private byte[] decodedBytes = new byte[]{};
    private String msgCoded;
    private String msgDecoded;
    private boolean fileCheck = false;
    final int maxTextAreaLength = 1024;

    @FXML
        public void initialize() {

        KeyGeneratorButton.setOnAction(event -> {
            plecak.generateKey(8);

            FirstKey.setText(Arrays.toString(plecak.getPublicKey())
                    .replace("[", "")
                    .replace("]", "")
                    .replace(" ", ""));

            SecondKey.setText(Arrays.toString(plecak.getPrivateKey())
                    .replace("[", "")
                    .replace("]", "")
                    .replace(" ", ""));

        });
        LoadKeyButton.setOnAction(event -> {
            LoadKeyFromFile();
            String keyText = FirstKey.getText().replaceAll("[\\[\\]\\s]", "");
            String[] keyParts = keyText.split(",");

            BigInteger[] publicKey = new BigInteger[keyParts.length];
            for (int i = 0; i < keyParts.length; i++) {
                publicKey[i] = new BigInteger(keyParts[i]);
            }

            plecak.setPublicKey(publicKey);

        });
        SaveKeyButton.setOnAction(event -> {
            if(FirstKey.getText() != null && SecondKey.getText() != null) {
                String keys = FirstKey.getText() + "\n" + SecondKey.getText();
                SaveKeyToFile(keys);
            }else{
                System.out.println("Wygeneruj najpierw klcuze by moc je zapisac");
            }

        });

        FileCheckBox.setOnAction(event -> {
         //   NormalTextArea.setEditable(fileCheck);
           // EncryptTextArea.setEditable(fileCheck);

            this.decodedBytes = new byte[]{};
            NormalTextArea.clear();
            this.encodedBytes = new BigInteger[]{};
            EncryptTextArea.clear();

            this.fileCheck = !this.fileCheck;
        });

        LoadNormalText.setOnAction(event -> {LoadTextFromFile(NormalTextArea, false);});
        SaveNormalText.setOnAction(event -> {
            byte[] data = NormalTextArea.getText().getBytes();
            SaveTextToFile(data, false);

        });

        LoadEncryptedText.setOnAction(event -> {LoadTextFromFile(EncryptTextArea, true);});
        SaveEncryptedText.setOnAction(event -> {
            byte[] data = EncryptTextArea.getText().getBytes();
            SaveTextToFile(data, true);

        });

        encryptButton.setOnAction(event -> {
            if (this.fileCheck) {
                if (this.decodedBytes.length == 0) {
                    System.err.println("Error: Empty buffer");
                    return;
                }

                try {
                    // Szyfrowanie danych
                   plecak.encrypt(this.decodedBytes);
                   this.encodedBytes = plecak.getEncodedBytes();

                   BigInteger[] encodedMsg = plecak.getEncodedBytes();

                    // Konwertujemy BigInteger[] na byte[]
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    for (BigInteger bigInteger : encodedMsg) {
                        byte[] bytes = bigInteger.toByteArray();
                        byteArrayOutputStream.write(bytes);
                    }

                    byte[] allBytes = byteArrayOutputStream.toByteArray();

                    // Kodowanie byte[] na Base64
                    msgCoded = Base64.getEncoder().encodeToString(allBytes);

                    EncryptTextArea.setText(Arrays.toString(encodedMsg)
                            .replace("[", "")
                            .replace("]", "")
                            .replace(",", "")
                            .replace(" ", ""));
                } catch (Exception e) {
                    System.err.println("Encryption failed: " + e.getMessage());
                }
            } else {
                String text = NormalTextArea.getText();

                if (text == null || text.isEmpty()){

                    System.err.println("Error: Text is empty");
                    return;
                }

                try {
                    // Szyfrowanie danych
                    BigInteger[] encrypted = plecak.encrypt(text.getBytes(StandardCharsets.UTF_8));
                    this.encodedBytes = encrypted;
                    EncryptTextArea.setText(Arrays.toString(encrypted)
                            .replace("[", "")
                            .replace("]", "")
                            .replace(",", "")
                            .replace(" ", ""));
                    System.out.println("Encoded Bytes: " + Arrays.toString(this.encodedBytes));
                } catch (Exception e) {
                    System.err.println("Encryption failed: " + e.getMessage());
                }
            }
        });

        decryptButton.setOnAction(event -> {
            if (this.fileCheck) {
                if (this.encodedBytes.length == 0) {
                    System.err.println("Error: Empty buffer");
                    return;
                }

                try {

                    this.decodedBytes = plecak.decrypt(this.encodedBytes);
                    NormalTextArea.setText(new String(this.decodedBytes, StandardCharsets.UTF_8));
                } catch (Exception e) {
                    System.err.println("Decryption failed: " + e.getMessage());
                }
            } else {
                String encryptedText = EncryptTextArea.getText();

                if (encryptedText == null || encryptedText.isEmpty()) {
                    System.err.println("Error: Text is empty or encodedBytes is empty");
                    return;
                }

                try {
                    BigInteger[] encd = plecak.getEncodedBytes();
                    this.decodedBytes = plecak.decrypt(encd);

                    // Wyświetlanie wyników w TextArea
                    NormalTextArea.setText(new String(this.decodedBytes, StandardCharsets.UTF_8));
                } catch (Exception e) {
                    System.err.println("Decryption failed: " + e.getMessage());
                }
            }
        });


    }

            private void SaveKeyToFile(String keys){
                FileChooser fileChooser = new FileChooser();
                fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("TXT", "*.txt"));
                File file = fileChooser.showSaveDialog(null);

                if(file != null){
                    try(FileWriter fileWriter = new FileWriter(file)){
                            fileWriter.write(keys);
                            System.out.println("Zapisano!");
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                }

            }
            //Wczytywanie kluczy z pliku (klucze sa wczytywane linia po lini i ustawianie w odpowiednich okienkach)
            private void LoadKeyFromFile(){
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Open Key File");
                fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("TXT", "*.txt"));
                File file = fileChooser.showOpenDialog(null);

                if(file != null){
                    try(BufferedReader reader = new BufferedReader(new FileReader(file))){
                        String temp;
                        StringBuilder keyData = new StringBuilder();

                        while ((temp = reader.readLine()) != null) {
                            keyData.append(temp).append("\n"); // czytanie po lini
                        }

                        //ustawianie kluczy do odpowiednich okienek
                        String[] keys = keyData.toString().split("\n");
                        // sprawdzenie czy w pliku mamy na pewno 2 klucze
                        if(keys.length >= 2){
                            FirstKey.setText(keys[0]);
                            SecondKey.setText(keys[1]);
                        }
                        System.out.println("Zaladowano klucze");
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            }

    private void LoadTextFromFile(TextArea textArea, boolean isEncrypted) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open File");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("All Files", "*.*"));

        File file = fileChooser.showOpenDialog(null);

        if (file != null) {
            try {
                byte[] fileData = Files.readAllBytes(file.toPath());
                BigInteger bigint = new BigInteger(fileData);
                String content = new String(fileData, StandardCharsets.UTF_8);

                if (fileCheck) {
                    if (isEncrypted) {
                        String[] values = content.split("\n");
                        BigInteger[] bigIntegers = new BigInteger[values.length];

                        for (int i = 0; i < values.length; i++) {
                            bigIntegers[i] = new BigInteger(values[i], 16);
                        }

                        this.encodedBytes = bigIntegers;

                        textArea.setText(Arrays.toString(bigIntegers)
                                .replace("[", "")
                                .replace("]", "")
                                .replace(",", "")
                                .replace(" ", ""));
                        System.out.println("Encoded Bytes: " + Arrays.toString(this.encodedBytes));
                    } else {
                        msgDecoded = Base64.getEncoder().encodeToString(fileData);
                        textArea.setText(new String(Base64.getDecoder().decode(msgDecoded)));
                        this.decodedBytes = fileData;
                    }
                } else {
                    String text = new String(fileData, StandardCharsets.UTF_8);
                    textArea.setText(text);

                    if (isEncrypted) {
                        String[] values = content.split("\n");
                        BigInteger[] bigIntegers = new BigInteger[values.length];

                        for (int i = 0; i < values.length; i++) {
                            bigIntegers[i] = new BigInteger(values[i], 16);
                        }

                        this.encodedBytes = bigIntegers;

                        textArea.setText(Arrays.toString(bigIntegers)
                                .replace("[", "")
                                .replace("]", "")
                                .replace(",", "")
                                .replace(" ", ""));
                    } else {
                        this.decodedBytes = fileData;
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void SaveTextToFile(byte[] data, boolean isEncrypted) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save File");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("All Files", "*.*"));

        File file = fileChooser.showSaveDialog(null);

        if (file != null) {
            try {
                if(fileCheck) {
                    if (isEncrypted) {
                        StringBuilder sb = new StringBuilder();
                        for (BigInteger bi : encodedBytes) {
                            sb.append(bi.toString(16)).append("\n"); // Wartość w systemie szesnastkowym
                        }
                        Files.write(file.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
                        System.out.println("Zapisano!");

                    } else {
                        byte[] decodedByteS = Base64.getDecoder().decode(msgDecoded);
                        Files.write(file.toPath(), decodedByteS);
                        System.out.println("Zapisano!");
                    }
                }else {
                    if (isEncrypted) {
                        String outputText = new String(data, StandardCharsets.UTF_8);
                        Files.write(file.toPath(), outputText.getBytes(StandardCharsets.UTF_8));

                    } else {
                        StringBuilder sb = new StringBuilder();
                        for (BigInteger bi : encodedBytes) {
                            sb.append(bi.toString(16)).append("\n");
                        }
                        Files.write(file.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
                        System.out.println("Zapisano!");
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}