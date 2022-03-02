package marin.ioana.ism.sap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;

public class OfflineAntivirus {

    public static String pathName = "C:\\Users\\Iuana\\Desktop\\Master\\SAP\\Files";
    public static Map<String,String> files = new HashMap<>();
    public static Map<String,String> existingFiles = new HashMap<>();
    public static SimpleDateFormat formatTimeStamp = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");

    public static String getHex(byte[] array) {
        String output = "";
        for(byte value : array) {
            output += String.format("%02x", value);
        }
        return output;
    }


    public static byte[] getHashMAC(String fileName, byte[] secretKey, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeyException {

        byte[] hashMAC = null;

        File file = new File(fileName);
        if(!file.exists()){
            throw new FileNotFoundException();
        }

        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secretKey, algorithm));

        FileInputStream fileInputStream = new FileInputStream(file);
        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);

        byte[] buffer = new byte[1024];
        int noBytesFromFile = bufferedInputStream.read(buffer);

        while (noBytesFromFile != -1){
            mac.update(buffer, 0, noBytesFromFile);
            noBytesFromFile = bufferedInputStream.read(buffer);
        }

        hashMAC = mac.doFinal();

        return hashMAC;
    }

    public static void storeHashMACValues() throws FileNotFoundException {

        PrintWriter printWriter = new PrintWriter("hashMACValues.txt");

        for(String file : files.keySet()){
            printWriter.println(file + " " + files.get(file));
        }
        printWriter.close();
    }

    public static void getHashMACValuesFromFile() throws IOException {

        existingFiles.clear();
        BufferedReader bufferedReader = new BufferedReader(new FileReader("hashMACValues.txt"));
        String line;
        while((line = bufferedReader.readLine()) != null){

            String items[] = line.split(" ");
            existingFiles.put(items[0].trim(), items[1].trim());

        }
    }

    public static void integrityCheck() throws IOException{

        getHashMACValuesFromFile();

        PrintWriter printWriter = new PrintWriter("report.txt");
        for(String file : files.keySet()){
            String timeStamp = formatTimeStamp.format(Calendar.getInstance().getTime());
            if(files.get(file).equals(existingFiles.get(file))){
                printWriter.println(file + " OK " + timeStamp);
            } else{
                printWriter.println(file + " CORRUPTED " + timeStamp);
            }
        }
        printWriter.close();
    }
    public static  void browseFolderContent(String path, byte[] secretKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException {

        File folder = new File(path);

        if(!folder.exists()){
            throw new FileNotFoundException();
        }

        if(folder.exists() && folder.isDirectory()){
            File[] entries = folder.listFiles();
            for(File entry : entries){
                if(entry.isDirectory()){
                    browseFolderContent(entry.getPath(), secretKey);
                } else{
                    byte[] hashMAC = getHashMAC(entry.getPath(), secretKey, "HmacSHA256");
                    files.put(entry.getName(),getHex(hashMAC));
                }
            }
        }
    }
    public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, ClassNotFoundException {

        File entry = new File(pathName);

        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        String option = "";
        String secretKey = "";

        do{
            System.out.println("************************************************************************");
            System.out.println("Hi :D This is your offline antivirus. Please choose an option:");
            System.out.println("1 - Status update");
            System.out.println("2 - Integrity check");
            System.out.println("0 - Exit");
            System.out.println("************************************************************************");

            option = bufferedReader.readLine();

            switch (option){
                case "1":
                    System.out.println("You have selected status update. Please type in the secret key:");
                    secretKey = bufferedReader.readLine();
                    files.clear();
                    browseFolderContent(entry.getAbsolutePath(), secretKey.getBytes());
                    storeHashMACValues();
                    System.out.println("Your new HashMAC values are stored in hashMACValues.txt in hexadecimal format. Please check the file.");
                    break;
                case "2":
                    System.out.println("You have selected integrity check.");
                    files.clear();
                    browseFolderContent(entry.getAbsolutePath(), secretKey.getBytes());
                    integrityCheck();
                    System.out.println("A new report has been generated based on what the antivirus found. Please check report.txt!");
                    break;
                case "0":
                    System.exit(0);
                    break;
            }
        } while(!option.equals("0"));

    }
}
