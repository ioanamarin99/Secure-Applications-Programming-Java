package marin.ioana.ism.sap;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class BruteForce {

    public static String hash = "16F65C9EDDD37E4C05F6813062F919F50C275DC7";


    public static byte[] getPasswordHash(String value) throws NoSuchAlgorithmException {

        byte[] md5HashValue = null;

        MessageDigest messageDigest = null;

        messageDigest = MessageDigest.getInstance("MD5");

        md5HashValue = messageDigest.digest(value.getBytes());

        byte[] sha1HashValue = null;

        messageDigest = MessageDigest.getInstance("SHA-1");

        sha1HashValue = messageDigest.digest(md5HashValue);

        return sha1HashValue;
    }

    public static String getHex(byte[] array) {
        String output = "";
        for(byte value : array) {
            output += String.format("%02X", value);
        }
        return output;
    }

    public static void crackThePassword() throws IOException, NoSuchProviderException, NoSuchAlgorithmException {

        BufferedReader bufferedReader = new BufferedReader(new FileReader("10-million-password-list-top-1000000.txt"));
        String password;
        boolean found = false;
        String prefix = "ism";
        while(((password = bufferedReader.readLine()) != null) && !found){

            byte[] hashedPassword = getPasswordHash(prefix+password);

            if(getHex(hashedPassword).equals(hash)){
                System.out.println("FOUND!! PASSWORD IS: " + password);
                found = true;
            }
        }

    }
    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, IOException {

        long tstart = System.currentTimeMillis();

         //do the brute force
        crackThePassword();

        long tfinal = System.currentTimeMillis();
        System.out.println("Duration is : " + (tfinal-tstart));
    }
}
