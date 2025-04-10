package org.example.plecak;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class TestSTH {
    public static void main(String[] args) throws Exception {

        Plecak pl = new Plecak();

        pl.generateKey(8);

        System.out.println(pl.getModulus());
        System.out.println(pl.getMultiplier());
        System.out.println(Arrays.toString(pl.getPublicKey())
                .replace("[", "")
                .replace("]", "")
                .replace(",", "")
                .replace(" ", ""));

        System.out.println(Arrays.toString(pl.getPrivateKey())
                .replace("[", "")
                .replace("]", "")
                .replace(",", "")
                .replace(" ", ""));


        String text = "Ala ma kota i psa";

        BigInteger[] encrypted = pl.encrypt(text.getBytes(StandardCharsets.UTF_8));

        System.out.println(Arrays.toString(encrypted));

        System.out.println("Encrypted: ");
        byte[] decrypted = pl.decrypt(encrypted);

        System.out.println(new String(decrypted, StandardCharsets.UTF_8));

    }
}
