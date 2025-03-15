package org.example.kryptografia;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.SecureRandom;

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

    private String K1, K2, K3;

    private DESX desx;

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

        LoadNormalText.setOnAction(event -> {LoadTextFromFile(NormalTextArea);});
        SaveNormalText.setOnAction(event -> {
            String text = NormalTextArea.getText();
            SaveTextToFile(text);
        });

        LoadEncryptedText.setOnAction(event -> {LoadTextFromFile(EncryptTextArea);});
        SaveEncryptedText.setOnAction(event -> {
            String text = EncryptTextArea.getText();
            SaveTextToFile(text);
        });

        encryptButton.setOnAction(event -> {
            String text = NormalTextArea.getText();

            try {
                String encryptedText = desx.encrypt(text);
                EncryptTextArea.setText(encryptedText);
            }catch (Exception e) {
                EncryptTextArea.setText("Blad");
            }
        });
        decryptButton.setOnAction(event -> {
            String text = EncryptTextArea.getText().trim();

            try{
                String decryptedText = desx.decrypt(text);
                NormalTextArea.setText(decryptedText);
            }catch (Exception e) {
                NormalTextArea.setText("Blad");
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

            private void LoadTextFromFile(TextArea textArea){
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Open Text File");
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("TXT", "*.txt"));
            File file = fileChooser.showOpenDialog(null);

            if(file != null){
                try(BufferedReader reader = new BufferedReader(new FileReader(file))){
                    String temp;
                    StringBuilder text = new StringBuilder();

                    while ((temp = reader.readLine()) != null) {
                        text.append(temp).append("\n"); // czytanie po lini

                    }

                    textArea.setText(text.toString());

                }catch (Exception e){
                    e.printStackTrace();
                }
            }

            }

            private void SaveTextToFile(String text){
            FileChooser fileChooser = new FileChooser();
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("TXT", "*.txt"));
            File file = fileChooser.showSaveDialog(null);

                if(file != null){
                    try(FileWriter fileWriter = new FileWriter(file)){
                        fileWriter.write(text);
                        System.out.println("Zapisano!");
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                }
            }
}