package org.example.plecak;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class Plecak {

    private final int keyLength = 512; // dlugosc klucza w bitach
    private final int keyBits = keyLength / 8; // dlugosc klucza w bajtach
    private BigInteger[] publicKey = new BigInteger[8]; // zaszyfrowana wersja klucza prywatnego
    private BigInteger[] privateKey = new BigInteger[8]; // superrosnaca sekwencja
    private BigInteger modulus; // modul M
    private BigInteger multiplier; // mnoznik W
    private BigInteger[] encodedBytes;// Zmienna do przechowywania zaszyfrowanych danych
    private byte[] decodedBytes;


    public Plecak() {
        this.encodedBytes = new BigInteger[0]; // Inicjalizacja pustych tablic
        this.decodedBytes = new byte[0];
    }


    public BigInteger getMultiplier() {
        return multiplier;
    }

    public void setMultiplier(BigInteger multiplier) {
        this.multiplier = multiplier;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    public BigInteger[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger[] privateKey) {
        this.privateKey = privateKey;
    }

    public BigInteger[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(BigInteger[] publicKey) {
        this.publicKey = publicKey;
    }

    // Getter do encodedBytes
    public BigInteger[] getEncodedBytes() {
        return encodedBytes;
    }

    // Getter do decodedBytes
    public byte[] getDecodedBytes() {
        return decodedBytes;
    }

    // generujemy kolejne wartosci kluczy
    public void generateKey(int size){
        Random rand = new Random();
        BigInteger sum = BigInteger.ZERO;
        BigInteger randomValue;

        // generowanie sekwencji superrosnacej
        for(int i = 0; i < size; i++){
            // losowanie kolejnych wartosci klucza (wiekszych od poprzednigo losowania)
            do {
                randomValue = new BigInteger(keyBits - 7 + 2 * i, rand);
            }while(randomValue.compareTo(sum) < 1);
                 sum = sum.add(randomValue);
            privateKey[i] = randomValue;
        }
        // Generowanie modulu i mnoznika
        modulus = sum.nextProbablePrime(); // zwraca liczbe wieksza od sumy ktora moze byc pierwsza
        multiplier = findMuliplier(modulus, rand);

        // obliczniae wartosci klucza publicznego

        for(int j = 0; j < size; j++){
            publicKey[j] = privateKey[j].multiply(multiplier).mod(modulus);
        }
    }


    private BigInteger findMuliplier(BigInteger modulus, Random random) {
        BigInteger multi;
        do {
            multi = new BigInteger(modulus.bitLength(), random);
        } while (
                multi.compareTo(BigInteger.ONE) <= 0 || multi.compareTo(modulus) >= 0 || !multi.gcd(modulus).equals(BigInteger.ONE));
        return multi;
    }

    public BigInteger[] encrypt(byte[] message){
        BigInteger[] sum = new BigInteger[message.length];
        for(int i = 0; i < message.length; i++){
            sum[i] = BigInteger.ZERO;
            // iterujemy po wszystkich bitach
            for(int j = 0; j < 8; j++) {
                if ((message[i] & (1 << j)) != 0) { // gdy bit to 1 dodajemy wartosc klucza na tym bicie
                    sum[i] = sum[i].add(publicKey[j]);
                }
            }
        }
        this.encodedBytes = sum;
        System.out.println("Encoded Bytes: " + Arrays.toString(this.encodedBytes));
        return sum;
    }

    public byte[] decrypt(BigInteger[] message){
        BigInteger reverseMulti = multiplier.modInverse(modulus);
        BigInteger[] reverseSum = new BigInteger[message.length];

        byte[] messageBytes = new byte[message.length];
        for(int i = 0; i < message.length; i++){
            byte value = 0;
            reverseSum[i] = message[i].multiply(reverseMulti).mod(modulus);
            for(int j = 7; j >= 0; j--) {
                if(reverseSum[i].compareTo(privateKey[j]) >= 0) {
                    value |= (1 << j);
                    reverseSum[i] = reverseSum[i].subtract(privateKey[j]);
                }
            }
            messageBytes[i] = value;
        }
        this.decodedBytes = messageBytes;
        return messageBytes;
    }
}
