package org.example.kryptografia;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class DESX {

    private byte[] K1, K2, K3;

    public DESX(String key1, String key2, String key3) {
        this.K1 = hexToByte(key1);
        this.K2 = hexToByte(key2);
        this.K3 = hexToByte(key3);
    }

    // szyforwanie
    public String encrypt(String plainText) {
        byte[] plainTextBytes = checkBytes(plainText.getBytes(StandardCharsets.UTF_8));

        StringBuilder encryptedText = new StringBuilder();

        for (int i = 0; i < plainTextBytes.length; i += 8) {
            byte[] block = Arrays.copyOfRange(plainTextBytes, i, i + 8);

            byte[] step1 = keyXor(block, K1); // pierwszy krok - szyfrowanie przy uzyciu pierwszego klucza i funkcji XOR

            byte[] step2 = desEncrypt(step1, K2); // drugie szyfrowanie przy uzyciu drugiego klucza wykorzystjac algorytm DES

            byte[] step3 = keyXor(step2, K3);// ostatnie szyfrowanie przy pomocy 3 klucza

            encryptedText.append(bytesToHexEncrypt(step3));
        }
        return encryptedText.toString();
    }

    public byte[] desEncrypt(byte[] data, byte[] key) {
        DES des = new DES();
        des.setMsg(data);
        des.setKey(key);
        des.run(1);
        byte[] result = des.getMsg();
        return result;

    }

    // funkcja zamieniajaca bity na postac HEX a potem string by poniez moc wyswietlic zaszyfrowany tekst
    private String bytesToHexEncrypt(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }

    // zamiana kluczy z HEX na bitowe
    private static byte[] hexToByte(String hex) {
        byte[] bytes = new BigInteger(hex, 16).toByteArray();
        if (bytes.length == 8) {
            return bytes; // jak mamy 8 to zwracamy
        }

        byte[] key = new byte[8];
        if (bytes.length > 8) {
            System.arraycopy(bytes, bytes.length - 8, key, 0, 8);
        } else {
            System.arraycopy(bytes, 0, key, 8 - bytes.length, bytes.length);
        }
        return key;
    }

    private static byte[] keyXor(byte[] message, byte[] key) {
        byte[] result = new byte[message.length];
        for (int i = 0; i < message.length; i++) {
            result[i] = (byte) ((message[i] ^ key[i % key.length])); // xorowanie wiadomosci i klucza
        }
        return result;
    }

    // funckja dzielaca tekst na bloki i dopelniajaca je zerami
    private static byte[] checkBytes(byte[] message) {
        int length = message.length;
        if(length % 8 == 0 ) {
            return message; // zwrocenie tekstu jesli nie trzeba go dopelniac
        }
        // dopelnienie tekstu zerami
        int newLength = ((length / 8) + 1)*8;

        byte[] result = new byte[newLength];
        System.arraycopy(message, 0, result, 0, length);

        for (int i = length; i < newLength; i++) {
            result[i] = 0x20; // wypelniamy spacjami by potem latwiej mozna bylo je usunac
        }

        return result;
    }

    // zmieniamy hex na bity do deszyfrowania
    private byte[] hexToBytesDecrypt(String hex){
        int tmp = hex.length();
        byte[] data = new byte[tmp/2];
        for(int i = 0; i < tmp; i+=2){
            data[i/2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
            + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }


    // deszyfrowanie - analogicznie do szyfrowania
    public String decrypt(String cipherText) {
        byte[] cipherTextBytes = hexToBytesDecrypt(cipherText);

        StringBuilder decryptedText = new StringBuilder();

        for (int i = 0; i < cipherTextBytes.length; i += 8) {
            byte[] block = Arrays.copyOfRange(cipherTextBytes, i, i + 8);

            byte[] step1 = keyXor(block, K3);
            byte[] step2 = desDescrypt(step1, K2);
            byte[] step3 = keyXor(step2, K1);

            decryptedText.append(new String(step3, StandardCharsets.UTF_8));

        }
        return decryptedText.toString().trim(); // usuwanie dodanych spacje
    }

    public byte[] desDescrypt(byte[] data, byte[] key) {
        DES des = new DES();
        des.setKey(key);
        des.setMsg(data);
        des.run(2);
        byte[] result = des.getMsg();
        return result;
    }

}
