package org.example.kryptografia;

public class TestDesx {
    public static void main(String[] args) throws Exception {
        // Przykładowe klucze (muszą być w formacie HEX, 16 znaków)
        String K1 = "0123456789ABCDEF";
        String K2 = "FEDCBA9876543210";
        String K3 = "0011223344556677";

        // Tworzenie instancji DESX
        DESX desx = new DESX(K1, K2, K3);

        // Przykładowy tekst do zaszyfrowania
        String plaintext = "Ala ma kota a kot ma ale Ala ma kota a kot ma ale Ala ma kota a kot ma ale";

        // Szyfrowanie
        String encrypted = desx.encrypt(plaintext);
        System.out.println("Zaszyfrowany tekst: " + encrypted);

        String decrypted = desx.decrypt(encrypted);
        System.out.println("\nOszyfrowany tekst: " + decrypted);

    }
}
