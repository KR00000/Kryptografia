package org.example.plecak;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class Plecak {

    private final int keyLength = 512; // dlugosc klucza w bitach
    private final int keyBits = keyLength / 8;
    private BigInteger[] publicKey = new BigInteger[512];
    private BigInteger[] privateKey = new BigInteger[512]; // superrosnaca sekwencja
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
                randomValue = new BigInteger(keyBits -7 + 2 * i, rand);
            }while(randomValue.compareTo(sum) < 1);
                 sum = sum.add(randomValue);
                 System.out.println(sum);
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

    private byte[] padMessage(byte[] message, int blockSize) {
        int paddingLength = blockSize - (message.length % blockSize);
        if (paddingLength == blockSize) return message; // Już pełny blok
        byte[] padded = Arrays.copyOf(message, message.length + paddingLength);
        return padded;
    }

    public BigInteger[] encrypt(byte[] message) {
        int blockSize = 64; // 64 bajty = 512 bity
        message = padMessage(message, blockSize); // dodaj padding
        int blockCount = message.length / blockSize;

        BigInteger[] result = new BigInteger[blockCount];

        for (int i = 0; i < blockCount; i++) {
            BigInteger sum = BigInteger.ZERO;
            for (int j = 0; j < blockSize; j++) {
                int byteVal = message[i * blockSize + j] & 0xFF;
                for (int bit = 0; bit < 8; bit++) {
                    if (((byteVal >> bit) & 1) == 1) {
                        int keyIndex = j * 8 + bit; // np. 0..511
                        sum = sum.add(publicKey[keyIndex]);
                    }
                }
            }
            result[i] = sum;
            System.out.println("Suma:" + result[i]);
        }
        this.encodedBytes = result;
        System.out.println("Encoded Bytes: " + Arrays.toString(this.encodedBytes));
        return result;
    }

//    public BigInteger[] encrypt(byte[] message){
//        BigInteger[] sum = new BigInteger[message.length];
//        for(int i = 0; i < message.length; i++){
//            sum[i] = BigInteger.ZERO;
//            // iterujemy po wszystkich bitach
//            for(int j = 0; j < 8; j++) {
//                if(((message[i] >> j) & 1) != 0)
//                { // gdy bit to 1 dodajemy wartosc klucza na tym bicie
//                    sum[i] = sum[i].add(publicKey[j]);
//                    System.out.println("Suma:" + sum[i]);
//                }
//            }
//        }
//        this.encodedBytes = sum;
//        System.out.println("Encoded Bytes: " + Arrays.toString(this.encodedBytes));
//        return sum;
//    }

    public byte[] decrypt(BigInteger[] message) {
        int blockSize = 64; // 512-bitowy klucz = 64 bajty
        byte[] result = new byte[message.length * blockSize];

        BigInteger reverseMulti = multiplier.modInverse(modulus);

        for (int i = 0; i < message.length; i++) {
            BigInteger sum = message[i].multiply(reverseMulti).mod(modulus);

            for (int j = 511; j >= 0; j--) { // odwrotnie!
                if (sum.compareTo(privateKey[j]) >= 0) {
                    sum = sum.subtract(privateKey[j]);
                    int byteIndex = j / 8;
                    int bitIndex = j % 8;
                    result[i * blockSize + byteIndex] |= (1 << bitIndex);
                }
            }
        }

        this.decodedBytes = result;
        return result;
    }
}
