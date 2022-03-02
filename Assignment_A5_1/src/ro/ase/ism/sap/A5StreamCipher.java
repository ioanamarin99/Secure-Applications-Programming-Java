package ro.ase.ism.sap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class A5StreamCipher {
    public static class WrongByteArraySize extends Exception{

    }

    public static int xRegisterTaps[] = {18, 17, 16, 13};
    public static int yRegisterTaps[] = {21, 20};
    public static int zRegisterTaps[] = {22, 21, 20, 7};

    public static int clockingBits[] = {8, 10, 10};

    public static byte xorRegisterTappedBits(byte[] register, int[] taps){

        byte result = register[taps[0]];

        for(int i = 1; i < taps.length; i++){
            result = (byte) (result ^ register[taps[i]]);
        }
        return result;
    }

    public static String getHex(byte[] array) {
        String output = "";
        for(byte value : array) {
            output += String.format("%02x ", value);
        }
        return output;
    }

    public static byte[] getBits(byte[] key, int size){

        byte[] keyBits = new byte[size];
        for(int i = 0; i < key.length; i++){
            byte currentByte = key[i];
            int shifter = 0;
            for(int j = 8 * i; j < 8 * (i + 1) && j < size; j++){
                   keyBits[j] = (byte) ((currentByte >>> shifter) & 1);
                   shifter++;
            }
        }

        return keyBits;
    }

    public static byte[] shiftRegister(byte[] register){

        for(int i = register.length - 1; i > 0; i--){
            register[i] = register[i-1];
        }
        register[0] = 0;
        return register;
    }

    public static List<Integer> getClockedRegisters(byte[] xRegister, byte[] yRegister, byte[] zRegister){

        List<Byte> bits = new ArrayList<>();
        bits.add(xRegister[clockingBits[0]]);
        bits.add(yRegister[clockingBits[1]]);
        bits.add(zRegister[clockingBits[2]]);

        int zeros = 0, ones = 0;
        for (byte b : bits){
            if(b == 0){
                zeros ++;
            } else{
                ones ++;
            }
        }

        List<Integer> clockedRegisters = new ArrayList<>();

        if(ones >= 2){
            for(int i = 0; i < bits.size(); i++){
                if(bits.get(i) == 1){
                    clockedRegisters.add(i);
                }
            }
        } else if(zeros >= 2){
            for(int i = 0; i < bits.size(); i++){
                if(bits.get(i) == 0){
                    clockedRegisters.add(i);
                }
            }
        }

        return clockedRegisters;
    }
    public static void registersInitialization(byte[] xRegister, byte[] yRegister, byte[] zRegister, String key, String frameNumber){

        byte[] keyBytes = key.getBytes();
        byte[] keyBits =  getBits(keyBytes, 64);


        //for 64 cycles, we mix the 64-bit secret key in the registers
        for(int i=0; i<keyBits.length; i++){

            byte xRegisterByte = (byte) (xorRegisterTappedBits(xRegister, xRegisterTaps) ^ keyBits[i]);
            xRegister = shiftRegister(xRegister);
            xRegister[0] = xRegisterByte;

            byte yRegisterByte = (byte) (xorRegisterTappedBits(yRegister, yRegisterTaps) ^ keyBits[i]);
            yRegister = shiftRegister(yRegister);
            yRegister[0] = yRegisterByte;

            byte zRegisterByte = (byte) (xorRegisterTappedBits(zRegister, zRegisterTaps) ^ keyBits[i]);
            zRegister = shiftRegister(zRegister);
            zRegister[0] = zRegisterByte;
        }


       byte [] frameNumberBytes = frameNumber.getBytes();
        byte[] frameNumberBits = getBits(frameNumberBytes, 22);

        //then, for 22 cycles, we mix the frame number in the registers
       for(int i = 0; i < frameNumberBits.length; i++){

           byte xRegisterByte = (byte) (xorRegisterTappedBits(xRegister, xRegisterTaps) ^ frameNumberBits[i]);
           xRegister = shiftRegister(xRegister);
           xRegister[0] = xRegisterByte;

           byte yRegisterByte = (byte) (xorRegisterTappedBits(yRegister, yRegisterTaps) ^ frameNumberBits[i]);
           yRegister = shiftRegister(yRegister);
           yRegister[0] = yRegisterByte;

           byte zRegisterByte = (byte) (xorRegisterTappedBits(zRegister, zRegisterTaps) ^ frameNumberBits[i]);
           zRegister = shiftRegister(zRegister);
           zRegister[0] = zRegisterByte;
       }

        //100-bit cycles
        for(int i = 0; i < 100; i++){

            List<Integer> clockedRegisters = getClockedRegisters(xRegister,yRegister,zRegister);
            for(int j = 0; j < clockedRegisters.size(); j++){

                if(clockedRegisters.get(j) == 0){
                    byte xRegisterByte = (byte) (xorRegisterTappedBits(xRegister, xRegisterTaps));
                    xRegister = shiftRegister(xRegister);
                    xRegister[0] = xRegisterByte;
                } else if(clockedRegisters.get(j) == 1){
                    byte yRegisterByte = (byte) (xorRegisterTappedBits(yRegister, yRegisterTaps));
                    yRegister = shiftRegister(yRegister);
                    yRegister[0] = yRegisterByte;
                } else if(clockedRegisters.get(j) == 2){
                    byte zRegisterByte = (byte) (xorRegisterTappedBits(zRegister, zRegisterTaps));
                    zRegister = shiftRegister(zRegister);
                    zRegister[0] = zRegisterByte;
                }
            }
        }

    }

    public static byte[] addBytes(byte[] byteArray, byte byteToAdd) {

        byte[] finalArray = new byte[byteArray.length + 1];

        for(int i = 0; i < finalArray.length; i++){
            if(i < byteArray.length) {
                finalArray[i] = byteArray[i];
            } else{
                finalArray[i] = byteToAdd;
            }
        }

        return finalArray;
    }

    public static byte[] A5Generator(String password, int sequenceNoBytes) {

        byte[] xRegister = new byte[19];
        byte[] yRegister = new byte[22];
        byte[] zRegister = new byte[23];

        String frameNumber = "123";
        registersInitialization(xRegister,yRegister,zRegister,password,frameNumber);

        byte[] sequenceBits = new byte[8 * sequenceNoBytes];

        for(int i = 0; i < 8 * sequenceNoBytes; i++){

            sequenceBits[i] = (byte) (xRegister[18] ^ yRegister[21] ^ zRegister[22]);

            List<Integer> clockedRegisters = getClockedRegisters(xRegister,yRegister,zRegister);

            for(int j = 0; j < clockedRegisters.size(); j++){

                if(clockedRegisters.get(j) == 0){
                    byte xRegisterByte = (byte) (xorRegisterTappedBits(xRegister, xRegisterTaps));
                    xRegister = shiftRegister(xRegister);
                    xRegister[0] = xRegisterByte;
                } else if(clockedRegisters.get(j) == 1){
                    byte yRegisterByte = (byte) (xorRegisterTappedBits(yRegister, yRegisterTaps));
                    yRegister = shiftRegister(yRegister);
                    yRegister[0] = yRegisterByte;
                } else if(clockedRegisters.get(j) == 2){
                    byte zRegisterByte = (byte) (xorRegisterTappedBits(zRegister, zRegisterTaps));
                    zRegister = shiftRegister(zRegister);
                    zRegister[0] = zRegisterByte;
                }
            }
        }

        byte[] sequenceBytes = new byte[]{};
        for(int i = 0; i < sequenceNoBytes; i++){
            byte currentByte = 0;
            int shifter = 0;
            for(int j = 8 * i; j < 8 * (i + 1); j++){
              currentByte += (byte) (sequenceBits[j] << shifter);

              if(currentByte < 0){
                  currentByte *= (-1);
              }
              shifter ++;
            }
            sequenceBytes = addBytes(sequenceBytes, currentByte);
        }


        return sequenceBytes;
    }

    public static int[] getPseudoNumberIntegers(byte[] bytesArray) throws WrongByteArraySize {
        if (bytesArray.length % 4 != 0) throw new WrongByteArraySize();
        int[] integers = new int[bytesArray.length / 4];
        int size = 0;

        for(int i = 0; i < integers.length; i++){
            int currentInteger = 0;
            for(int j = i * 4; j < (i+1) * 4; j++){
                currentInteger += bytesArray[j];
            }
        }
        return integers;
    }
    public static void main(String[] args)  {


       String password = "asdfghjk";
       byte[] sequence = A5Generator(password, 45);
        System.out.println("The byte sequence: " + getHex(sequence));


        String password2 = "password";
        sequence = A5Generator(password2, 23);
        System.out.println("The byte sequence: " + getHex(sequence));

        try{
            getPseudoNumberIntegers(sequence);
        } catch (WrongByteArraySize ex){
            System.out.println("The size of the input byte array is not valid!");
        }



    }
}
