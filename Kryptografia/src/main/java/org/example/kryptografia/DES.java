package org.example.kryptografia;

import java.util.BitSet;

public class DES {

    private final Permutations v;
    private byte[] key, msg;
    private byte[][] subKeys;
    private byte[] leftSide, rightSide;

    DES() {
        this.v = new Permutations();
        leftSide = null;
        rightSide = null;
    }

    public byte[] getMsg(){
        return msg;
    }

    public void setMsg(byte[] msg) {
        this.msg = msg;
    }

    public byte[] getKey(){
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
        generateSubKeys();
    }

    public void run(int mode) {

        msg = bitShuffle(msg, v.startPermutation); // Permutacja początkowa
        divideMsg();// Podział wiadomości na dwie części
        proceedIterations(mode);
    }

    private void proceedIterations(int mode) {
        int iteration = subKeys.length;
        for (int i = 0; i < iteration; i++) {
            byte[] oldRightSide = rightSide;
            rightSide = bitShuffle(rightSide, v.extendedPermutation);
            rightSide = byteXOR(rightSide, mode == 1 ? subKeys[i] : subKeys[iteration - i - 1]);
            rightSide = doSBox(rightSide);
            rightSide = bitShuffle(rightSide, v.pBox);
            rightSide = byteXOR(leftSide, rightSide);
            leftSide = oldRightSide;
        }
        msg = byteConcat(rightSide, v.startPermutation.length / 2, leftSide, v.startPermutation.length / 2);
        msg = bitShuffle(msg, v.endPermutation);
    }

    private byte[] doSBox(byte[] data) {
        data = byteSplit86(data);
        byte[] output = new byte[data.length / 2];
        for (int i = 0, firstSBoxValue = 0; i < data.length; i++) {
            byte sixBitsFragment = data[i];
            int rowNumb = 2 * (sixBitsFragment >> 7 & 0x0001) + (sixBitsFragment >> 2 & 0x0001);
            int columnNumb = sixBitsFragment >> 3 & 0x000F;
            int secondSBoxValue = v.sBox[64 * i + 16 * rowNumb + columnNumb];
            if (i % 2 == 0)
                firstSBoxValue = secondSBoxValue;
            else
                output[i / 2] = createByteFromSBoxValues(firstSBoxValue, secondSBoxValue);
        }
        return output;
    }

    private byte createByteFromSBoxValues(int firstSBoxValue, int secondSBoxValue) {
        return (byte) (16 * firstSBoxValue + secondSBoxValue);
    }


    public void divideMsg() {
        int bitNumber = (msg.length * 8) /2;
        leftSide = byteSplit(msg, 0 , bitNumber);
        rightSide = byteSplit(msg, bitNumber, bitNumber);
    }

    private void generateSubKeys(){
        byte[] keyPC1 = bitShuffle(key,v.PC1);
        byte[] c = byteSplit(keyPC1, 0, 28);
        byte[] d = byteSplit(keyPC1, 28, 28);
        byte[] cd;
        subKeys = new byte[v.shifts.length][];
        for (int i = 0; i < v.shifts.length; i++) {
            c = leftShift(c, v.shifts[i]);
            d = leftShift(d, v.shifts[i]);
            cd = byteConcat(c, 28, d, 28);
            subKeys[i] = bitShuffle(cd, v.PC2);
        }
    }

    private byte[] leftShift(byte[] input, int shiftNumb) {
        byte[] out = new byte[4];
        int halfKeySize = 28;
        boolean bit;
        for (int i = 0; i < halfKeySize; i++) {
            bit = bitCheck(input, (i + shiftNumb) % halfKeySize);
            bitSet(out, i, bit);
        }
        return out;
    }

    private byte[] bitShuffle(byte[] input, int[] permTable) {
        byte[] output = prepareOutput(permTable.length);
        boolean bit;
        for (int i = 0; i < permTable.length; i++) {
            bit = bitCheck(input, permTable[i] - 1);
            bitSet(output, i, bit);
        }
        return output;
    }

    private boolean bitCheck(byte[] data, int index) {
        int Byte = index / 8;
        int Bit = index % 8;
        return (data[Byte] >> (8 - (Bit + 1)) & 1) == 1;
    }

    private void bitSet(byte[] data, int index, boolean bit) {
        int Byte = index / 8;
        int Bit = index % 8;
        if(bit) {
            data[Byte] |= 0x80 >> Bit;
        } else {
            data[Byte] &= ~(0x80 >> Bit);
        }
    }

    private byte[] prepareOutput(int length) {
        int bytesNumb = ((length - 1) / 8) + 1;
        return new byte[bytesNumb];
    }

    byte[] byteXOR(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    private byte[] byteSplit86(byte[] input) {
        int bytesNumber = 8;
        boolean val;
        byte[] output = new byte[bytesNumber];
        for (int i = 0; i < bytesNumber; i++) {
            for (int j = 0; j < 6; j++) {
                val = bitCheck(input, (6 * i) + j);
                bitSet(output, (8 * i) + j, val);
            }
        }
        return output;
    }

    byte[] byteSplit(byte[] input, int index, int length) {
        boolean bit;
        byte[] output = prepareOutput(length);
        for (int i = 0; i < length; i++) {
            bit = bitCheck(input, index + i);
            bitSet(output, i, bit);
        }
        return output;
    }

    byte[] byteConcat(byte[] a, int aLength, byte[] b, int bLength) {
        boolean bit;
        byte[] output = prepareOutput(aLength + bLength);
        int i = 0;
        for (; i < aLength; i++) {
            bit = bitCheck(a, i);
            bitSet(output, i, bit);
        }
        for (int j = 0; j < bLength; j++, i++) {
            bit = bitCheck(b, j);
            bitSet(output, i, bit);
        }
        return output;
    }

}


