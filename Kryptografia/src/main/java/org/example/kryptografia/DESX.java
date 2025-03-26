package org.example.kryptografia;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class DESX {

    private byte[] K1, K2, K3;
    private byte[] encodedBytes; // Zmienna do przechowywania zaszyfrowanych danych
    private byte[] decodedBytes; // Zmienna do przechowywania odszyfrowanych danych

    public DESX(String key1, String key2, String key3) {
        this.K1 = hexToByte(key1);
        this.K2 = hexToByte(key2);
        this.K3 = hexToByte(key3);
        this.encodedBytes = new byte[0]; // Inicjalizacja pustych tablic
        this.decodedBytes = new byte[0];
    }

    // Szyfrowanie - teraz zapisuje wynik do encodedBytes
    public byte[] encrypt(byte[] plainTextBytes) {
        plainTextBytes = checkBytes(plainTextBytes);
        printHexDebug(plainTextBytes, "Plaintext (after padding)");

        ByteArrayOutputStream encryptedText = new ByteArrayOutputStream();

        for (int i = 0; i < plainTextBytes.length; i += 8) {
            byte[] block = Arrays.copyOfRange(plainTextBytes, i, i + 8);

            byte[] step1 = keyXor(block, K1); // pierwszy krok - szyfrowanie przy uzyciu pierwszego klucza i funkcji XOR

            byte[] step2 = desEncrypt(step1, K2); // drugie szyfrowanie przy uzyciu drugiego klucza

            byte[] step3 = keyXor(step2, K3); // ostatnie szyfrowanie przy pomocy 3 klucza

            encryptedText.write(step3, 0, step3.length);
        }

        this.encodedBytes = encryptedText.toByteArray(); // Zapisanie zaszyfrowanych danych do encodedBytes
        printHexDebug(this.encodedBytes, "Encrypted data");
        return this.encodedBytes;
    }

    // Deszyfrowanie - zapisuje wynik do decodedBytes
    public byte[] decrypt(byte[] cipherTextBytes) {
        printHexDebug(cipherTextBytes, "Ciphertext (before decryption)");

        ByteArrayOutputStream decryptedText = new ByteArrayOutputStream();

        for (int i = 0; i < cipherTextBytes.length; i += 8) {
            byte[] block = Arrays.copyOfRange(cipherTextBytes, i, i + 8);

            byte[] step1 = keyXor(block, K3);
            byte[] step2 = desDescrypt(step1, K2);
            byte[] step3 = keyXor(step2, K1);

            decryptedText.write(step3, 0, step3.length);
        }

        this.decodedBytes = removePadding(decryptedText.toByteArray()); // Zapisanie odszyfrowanych danych do decodedBytes
        printHexDebug(this.decodedBytes, "Decrypted data");
        return this.decodedBytes;
    }

    // Getter do encodedBytes
    public byte[] getEncodedBytes() {
        return encodedBytes;
    }

    // Getter do decodedBytes
    public byte[] getDecodedBytes() {
        return decodedBytes;
    }

    // Funkcje pomocnicze
    private byte[] desEncrypt(byte[] data, byte[] key) {
        DES des = new DES();
        des.setMsg(data);
        des.setKey(key);
        des.run(1);
        return des.getMsg();
    }

    private byte[] desDescrypt(byte[] data, byte[] key) {
        DES des = new DES();
        des.setKey(key);
        des.setMsg(data);
        des.run(2);
        return des.getMsg();
    }

    private static byte[] keyXor(byte[] message, byte[] key) {
        byte[] result = new byte[message.length];
        for (int i = 0; i < message.length; i++) {
            result[i] = (byte) ((message[i] ^ key[i % key.length]));
        }
        return result;
    }

    private static byte[] checkBytes(byte[] message) {
        int length = message.length;
        if (length % 8 == 0) {
            return message; // Jeśli długość jest już wielokrotnością 8, zwróć dane
        }

        int newLength = ((length / 8) + 1) * 8;
        byte[] result = new byte[newLength];
        System.arraycopy(message, 0, result, 0, length);
        Arrays.fill(result, length, newLength, (byte) 0x00);
        return result;
    }

    private static byte[] removePadding(byte[] data) {
        int lastIndex = data.length;
        while (lastIndex > 0 && data[lastIndex - 1] == 0x00) {
            lastIndex--;
        }
        return Arrays.copyOf(data, lastIndex);
    }

    private void printHexDebug(byte[] data, String label) {
        System.out.print(label + " : ");
        for (int i = 0; i < Math.min(16, data.length); i++) {
            System.out.printf("%02X ", data[i]);
        }
        System.out.println();
    }

    private static byte[] hexToByte(String hex) {
        byte[] bytes = new BigInteger(hex, 16).toByteArray();
        if (bytes.length == 8) {
            return bytes;
        }

        byte[] key = new byte[8];
        if (bytes.length > 8) {
            System.arraycopy(bytes, bytes.length - 8, key, 0, 8);
        } else {
            System.arraycopy(bytes, 0, key, 8 - bytes.length, bytes.length);
        }
        return key;
    }

    public static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder();
        if (src == null || src.length <= 0) {
            return "";
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }

    // funkcja zamieniajaca bity na postac HEX a potem string by poniez moc wyswietlic zaszyfrowany tekst
    String bytesToHexEncrypt(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }

    // zmieniamy hex na bity do deszyfrowania
    byte[] hexToBytesDecrypt(String hex){
        int tmp = hex.length();
        byte[] data = new byte[tmp/2];
        for(int i = 0; i < tmp; i+=2){
            data[i/2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    //zamiana tablicy bajtów na Stringa
    public static String bytesToString(byte[] src) {
        return new String(src);
    }

}
