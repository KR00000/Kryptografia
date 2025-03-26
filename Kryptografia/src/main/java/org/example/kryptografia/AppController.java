package org.example.kryptografia;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;

import java.io.*;
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
    private TextField ThirdKey;

    @FXML
    private TextArea NormalTextArea;

    @FXML
    private TextArea EncryptTextArea;

    @FXML
    private CheckBox FileCheckBox;

    private String K1, K2, K3;

    private DESX desx;

    private byte[] encodedBytes = new byte[]{};
    private byte[] decodedBytes = new byte[]{};
    private String msgCoded;
    private String msgDecoded;
    private boolean fileCheck = false;
    final int maxTextAreaLength = 1024;

    @FXML
        public void initialize() {

        KeyGeneratorButton.setOnAction(event -> {
             K1 = keyGenerator(8);
             K2 = keyGenerator(8);
             K3 = keyGenerator(8);

            FirstKey.setText(K1);
            SecondKey.setText(K2);
            ThirdKey.setText(K3);

            desx = new DESX(K1, K2, K3);

        });
        LoadKeyButton.setOnAction(event -> {
            LoadKeyFromFile();
            K1 = FirstKey.getText();
            K2 = SecondKey.getText();
            K3 = ThirdKey.getText();
            desx = new DESX(K1, K2, K3);// ustawianie kluczy po wczytaniu (inaczej bedzie null)
        });
        SaveKeyButton.setOnAction(event -> {
            if(K1 != null && K2 != null && K3 != null) {
                String keys = K1 + "\n" + K2 + "\n" + K3;
                SaveKeyToFile(keys);
            }else{
                System.out.println("Wygeneruj najpierw klcuze by moc je zapisac");
            }

        });

        FileCheckBox.setOnAction(event -> {
            NormalTextArea.setEditable(fileCheck);
            EncryptTextArea.setEditable(fileCheck);

            this.decodedBytes = new byte[]{};
            setTextArea(NormalTextArea, DESX.bytesToHexString(this.decodedBytes));
            this.encodedBytes = new byte[]{};
            setTextArea(EncryptTextArea, DESX.bytesToHexString(this.encodedBytes));

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
                    // Jeżeli buffer jest pusty, wyświetlamy komunikat o błędzie w konsoli
                    System.err.println("Error: Empty buffer");
                    return;
                }

                try {
                    // Tworzymy instancję DESX przy pomocy kluczy
                    desx = new DESX(K1, K2, K3);

                    // Szyfrowanie danych
                    desx.encrypt(this.decodedBytes);
                    this.encodedBytes = desx.getEncodedBytes();

                    msgCoded = Base64.getEncoder().encodeToString(desx.getEncodedBytes());

                    String hexString = desx.bytesToHexEncrypt(Base64.getDecoder().decode(msgCoded));

                    // Wyświetlamy zaszyfrowany tekst w EncryptTextArea
                    EncryptTextArea.setText(hexString);
                } catch (Exception e) {
                    // Wyświetlamy komunikat o błędzie w konsoli
                    System.err.println("Encryption failed: " + e.getMessage());
                }
            } else {
                // Jeśli nie pracujemy z plikiem, to szyfrujemy tekst z NormalTextArea
                String text = NormalTextArea.getText();

                if (text == null || text.isEmpty()) {
                    // Jeżeli tekst jest pusty, wyświetlamy komunikat o błędzie w konsoli
                    System.err.println("Error: Text is empty");
                    return;
                }

                try {
                    // Tworzymy instancję DESX przy pomocy kluczy
                    desx = new DESX(K1, K2, K3);

                    // Szyfrowanie danych
                    desx.encrypt(text.getBytes(StandardCharsets.UTF_8));

                    msgCoded = Base64.getEncoder().encodeToString(desx.getEncodedBytes());

                    String hexString = desx.bytesToHexEncrypt(Base64.getDecoder().decode(msgCoded));

                    // Wyświetlamy zaszyfrowany tekst w EncryptTextArea
                    EncryptTextArea.setText(hexString);
                } catch (Exception e) {
                    // Wyświetlamy komunikat o błędzie w konsoli
                    System.err.println("Encryption failed: " + e.getMessage());
                }
            }
        });
        decryptButton.setOnAction(event -> {
            if (this.fileCheck) {
                if (this.encodedBytes.length == 0) {
                    // Jeśli buffer jest pusty, wypisujemy komunikat o błędzie
                    System.err.println("Error: Empty buffer");
                    return;
                }

                try {
                    // Tworzymy instancję DESX z kluczami i przeprowadzamy deszyfrowanie
                    desx = new DESX(K1, K2, K3);
                    this.decodedBytes = desx.decrypt(this.encodedBytes);

                    // Jeśli chcesz wyświetlić wynik w `NormalTextArea`, używamy tego:
                    printHexDebug(this.decodedBytes, "Decrypted data");
                    NormalTextArea.setText(DESX.bytesToString(this.decodedBytes));
                } catch (Exception e) {
                    // W przypadku błędu wypisujemy komunikat w konsoli
                    System.err.println("Decryption failed: " + e.getMessage());
                }
            } else {
                // Jeśli nie pracujemy z plikiem, deszyfrujemy dane tekstowe z `EncryptTextArea`
                String encryptedText = EncryptTextArea.getText();

                if (encryptedText == null || encryptedText.isEmpty()) {
                    // Jeżeli tekst w polu jest pusty, wypisujemy komunikat o błędzie
                    System.err.println("Error: Text is empty");
                    return;
                }

                try {
                    // Przekształcamy tekst HEX na bajty
                    byte[] encryptedBytes = desx.hexToBytesDecrypt(encryptedText);

                    // Tworzymy instancję DESX i przeprowadzamy deszyfrowanie
                    this.decodedBytes = desx.decrypt(encryptedBytes);
                    printHexDebug(this.decodedBytes, "Decrypted data");
                    // Wyświetlamy wynik w `NormalTextArea`
                    NormalTextArea.setText(DESX.bytesToString(this.decodedBytes));
                } catch (Exception e) {
                    // W przypadku błędu wypisujemy komunikat w konsoli
                    System.err.println("Decryption failed: " + e.getMessage());
                }
            }
        });

    }

            // generowanie kluczy
            public static String keyGenerator(int byteLength){
            SecureRandom random = new SecureRandom();
            byte[] key = new byte[byteLength];
            random.nextBytes(key);

            // zamiana na postac HEX
            StringBuilder toHex = new StringBuilder();
            for (byte b : key) {
                toHex.append(String.format("%02X", b));
                }
                return toHex.toString();
            }

            // zapis kluczy do pliku(kazdy klucz w nowej lini)
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
                        // sprawdzenie czy w pliku mamy na pewno 3 klucze
                        if(keys.length >= 3){
                            FirstKey.setText(keys[0]);
                            SecondKey.setText(keys[1]);
                            ThirdKey.setText(keys[2]);
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

                if (fileCheck) {
                    // Odczyt jako Base64 (szyfrowane dane)
                    if (isEncrypted) {
                        msgCoded = Base64.getEncoder().encodeToString(fileData);
                        textArea.setText(msgCoded);
                        this.encodedBytes = fileData;
                    } else {
                        msgDecoded = Base64.getEncoder().encodeToString(fileData);
                        textArea.setText(new String(Base64.getDecoder().decode(msgDecoded)));
                        this.decodedBytes = fileData;
                    }
                } else {
                    // Odczyt jako czysty tekst UTF-8
                    String text = new String(fileData, StandardCharsets.UTF_8);
                    textArea.setText(text);

                    if (isEncrypted) {
                        this.encodedBytes = fileData;
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
                        byte[] encodedByteS = Base64.getDecoder().decode(msgCoded);
                        Files.write(file.toPath(), encodedByteS);
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
                        String outputText = new String(data, StandardCharsets.UTF_8);
                        Files.write(file.toPath(), outputText.getBytes(StandardCharsets.UTF_8));
                        System.out.println("Zapisano!");
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }


    private void setTextArea(TextArea ta, String str) {
        if (str == null) {
            return;
        }
        if (str.length() > this.maxTextAreaLength) {
            str = str.substring(0, this.maxTextAreaLength);
        }
        ta.setText(str);
    }

    private void printHexDebug(byte[] data, String label) {
        System.out.print(label + " : ");
        for (int i = 0; i < Math.min(16, data.length); i++) {
            System.out.printf("%02X ", data[i]);
        }
        System.out.println();
    }
}