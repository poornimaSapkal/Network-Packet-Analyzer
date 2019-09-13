import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class packetReader {

    static FileInputStream fin;

    /**
     * The readBytes function reads the specified number of bytes from the file.
     *
     * @param numberOfBytesToRead the number of bytes that need to be read from the file.
     * @return returns an array of bytes that were read from the file
     */
    public static byte[] readBytes(int numberOfBytesToRead) {
        byte[] bytes = new byte[numberOfBytesToRead];
        for (int i = 0; i < numberOfBytesToRead; i++) {
            try {
                bytes[i] = (byte)fin.read();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return bytes;
    }

    /**
     * This function takes in a byte value and converts that value to its hexadecimal equivalent
     *
     * @param byteToConvert the byte that needs to be converted to its hexadecimal equivalent.
     * @return returns a hexadecimal equivalent of the byte passed in as a parameter.
     */
    public static  String convertToHex(byte byteToConvert){
        return String.format("%02x", byteToConvert);
    }

    /**
     * This function takes in an array of bytes and converts the bytes to their hexadecimal equivalent.
     * It uses string concatenation operation to convert the array of bytes as a single hexadecimal
     * string.
     *
     * @param byteToConvert the byte array that needs to be converted to its hexadecimal equivalent.
     * @return returns a string of the hexadecimal equivalent of the bytes in the array.
     */

    public static  String convertToHex(byte[] byteToConvert){
        String hexEquivalent = "";
        for(int i =0; i<byteToConvert.length; i++){
            hexEquivalent += String.format("%02x", byteToConvert[i]);
        }
        return hexEquivalent;
    }

    /**
     * This function takes in an array of bytes and converts the bytes to their char equivalent.
     * It checks if the ascii value of the byte lies in the range 65-122. If it does, it prints that
     * character or it prints a period ('.') .
     *
     * @param bytesOfData the byte array which needs to be converted to its char equivalent
     * @return returns the char equivalent of the bytes in the array
     */

    public static String convertToChar(byte[] bytesOfData){
        String charEquivalent = "";
        for(int i=0; i<bytesOfData.length; i++){
//            charEquivalent+= (char)(bytesOfData[i]& 0xff);
            int asciiEquivalent = (int) bytesOfData[i];
            if((65<=asciiEquivalent)&&(asciiEquivalent<=122)){
                charEquivalent+= (char)asciiEquivalent;
            } else {
                charEquivalent+= ".";
            }
        }
        return "|"+charEquivalent+"|";
    }

    /**
     * This function process the data that will be displayed at the end. It takes in an array of bytes and converts
     * it to its hexadecimal equivalent and char equivalent simultaneously. It then concatenates the result and sends it
     * backed to the calling function.
     *
     * @param bytesOfData the array of bytes that need to be converted to their hexadecimal equivalent.
     * @return returns that hexadecimal and char equivalent of the bytes
     */

    public static String convertToHexForData(byte[] bytesOfData){
        String hexEquivalent = "";
        for(int i=0; i< bytesOfData.length-2; i++){
            hexEquivalent+= convertToHex(bytesOfData[i]);
            hexEquivalent+= convertToHex(bytesOfData[i+1]);
            i+=2;
            hexEquivalent+= " ";
        }
        String charEquivalent = convertToChar(bytesOfData);
        return hexEquivalent+"     "+charEquivalent;
    }


    /**
     * This function takes in a hexadecimal string as a parameter and converts it to its decimal equivalent.
     *
     * @param hexNumber the hexadecimal number that needs to be converted to its equivalent decimal.
     * @return returns the decimal equivalent of the hexadecimal number.
     */

    public static long hexToDecimal(String hexNumber){
        long decimal_equivalent = Long.parseLong(hexNumber, 16);
        return decimal_equivalent;
    }

    /**
     *This function takes in the array of bytes that represent the mac address and it converts those
     * bytes to its hexadecimal equivalent and appends a colon (':') after every byte to match the standard
     * convention of what a mac address looks like.
     *
     * @param bytesToProcess the bytes of the mac address that need to be processed
     * @return mac address for the specified bytes in the correct format.
     */

    public static String processMacAddress(byte[] bytesToProcess){
        String macAddress = "";
        for(int i =0; i< bytesToProcess.length; i++){
            String bytesToHex = convertToHex(bytesToProcess[i]);
            macAddress += bytesToHex + ':';
        }
        return macAddress.substring(0,macAddress.length()-1);
    }

    public static String processIpAddress(String ipInHex){
        String ipAddress="";
        for(int i=0;i<ipInHex.length();i++){
            String split_string = ipInHex.substring(i,i+2);
            i++;
            int decimal_equivalent = Integer.parseInt(split_string, 16);
            ipAddress += decimal_equivalent+".";
        }
        return ipAddress.substring(0, ipAddress.length()-1);
    }

    public static void processEther(int packetSize){

        byte[] destinationBytes = readBytes(6);
        byte[] sourceBytes = readBytes(6);
        byte[] etherBytes = readBytes(2);

        String destinationMacAddress = processMacAddress(destinationBytes);
        String sourceMacAddress = processMacAddress(sourceBytes);
        String etherType = convertToHex(etherBytes);

        System.out.println("ETHER: ------Ether header------");
        System.out.println("ETHER:");
        System.out.println("ETHER:  Packet Size = " +packetSize);
        System.out.println("ETHER:  Destination = " +destinationMacAddress);
        System.out.println("ETHER:  Source      = " +sourceMacAddress);
        System.out.println("ETHER:  Ether type  = " +etherType);
        System.out.println("ETHER: ");

    }

    public static void processDataBytes(long protocol){
        String protocolName = "";
        if(protocol == 1){
            protocolName = "ICMP";
        } else if (protocol == 6){
            protocolName = "TCP";
        } else if (protocol == 17){
            protocolName = "UDP";
        }
        //change this to check if there are 64 bytes available
        System.out.println(protocolName + ":  Data: (first 64 bytes)");
        for(int i=0; i<4; i++){
            byte[] dataBytes = readBytes(16);
            String hexEquivalent = convertToHexForData(dataBytes);
            System.out.println(protocolName+":  "+ hexEquivalent);
        }

    }

    public static long processIp(){

        byte[] versionAndHeaderLengthBytes = readBytes(1);
        byte[] typeOfServiceBytes = readBytes(1);
        byte[] totalLengthBytes = readBytes(2);
        byte[] identificationBytes = readBytes(2);
        byte[] flagAndFragmentOffsetBytes = readBytes(2);
        byte[] timeToLiveBytes = readBytes(1);
        byte[] protocolBytes = readBytes(1);
        byte[] headerChecksumBytes = readBytes(2);
        byte[] sourceAddressBytes = readBytes(4);
        byte[] destinationAddressBytes = readBytes(4);

        String typeOfService = convertToHex(typeOfServiceBytes);
        String totalLengthBytesHex = convertToHex(totalLengthBytes);
        String identificationBytesHex = convertToHex(identificationBytes);
        String timeToLiveHex = convertToHex(timeToLiveBytes);
        String protocolHex = convertToHex(protocolBytes);
        String headerChecksum = convertToHex(headerChecksumBytes);
        String sourceAddressHex = convertToHex(sourceAddressBytes);
        String destinationAddressHex = convertToHex(destinationAddressBytes);

        byte versionAndHeaderLength = versionAndHeaderLengthBytes[0];
        byte version = (byte)(versionAndHeaderLength>>4 &15);
        byte headerLengthByte = (byte)(versionAndHeaderLength & 15);
        int headerLength = headerLengthByte * 4;

        byte typeOfServiceByte = (byte)(typeOfServiceBytes[0] >> 5 & 7);

        long totalLength = hexToDecimal(totalLengthBytesHex);
        long identification = hexToDecimal(identificationBytesHex);
        long timeToLive = hexToDecimal(timeToLiveHex);
        long protocol = hexToDecimal(protocolHex);
        String sourceAddress = processIpAddress(sourceAddressHex);
        String destinationAddress = processIpAddress(destinationAddressHex);

        //type of service code:

        byte delayBit = (byte)(typeOfServiceBytes[0]>>4 & 1);
        byte throughputBit = (byte) (typeOfServiceBytes[0]>>3 &1);
        byte reliabilityBit = (byte) (typeOfServiceBytes[0]>>2 & 1);
        int delay, throughput, reliability;
        String delayMessage, throughputMessage, reliabilityMessage;

        if ((int)delayBit == 1){
            delay = 1;
            delayMessage = " low delay";
        } else {
            delay = 0;
            delayMessage = " normal delay";
        }

        if ((int) throughputBit == 1){
            throughput = 1;
            throughputMessage = " high throughput";
        } else {
            throughput = 0;
            throughputMessage = " normal throughput";
        }

        if((int) reliabilityBit == 1){
            reliability = 1;
            reliabilityMessage = " high reliability";
        } else {
            reliability = 0;
            reliabilityMessage = " normal reliability";
        }

        //flag
        byte flagByte = (byte)(flagAndFragmentOffsetBytes[0] >> 5 & 7);
        int flag = (int) flagByte;

        byte fragmentBit1 = (byte)(flagAndFragmentOffsetBytes[0] >> 6 & 1);
        byte fragmentBit2 = (byte)(flagAndFragmentOffsetBytes[0] >> 5 &1);

        //fragment offset
        byte fiveBitsFromFirstByte = (byte)(flagAndFragmentOffsetBytes[0] & 31);
        byte otherHalfOfFragmentOffset = flagAndFragmentOffsetBytes[1];
        int fragmentOffset = (int)fiveBitsFromFirstByte + (int)otherHalfOfFragmentOffset;


        System.out.println("IP:  -----IP Header -----");
        System.out.println("IP:");
        System.out.println("IP:  Version = " + (int)version);
        System.out.println("IP:  Header length = " +headerLength +" bytes");
        System.out.println("IP:  Type of service = 0x" +typeOfService);
        System.out.println("IP:     xxx. .... = " + (int)typeOfServiceByte+ " (precedence)");
        System.out.println("IP:     ..." +delay+" .... = " +delayMessage);
        System.out.println("IP:     .... "+throughput+"... = " +throughputMessage);
        System.out.println("IP:     .... .."+reliability+".. = " +reliabilityMessage);
        //type of service stuff
        System.out.println("IP:  Total length = " + totalLength + " bytes");
        System.out.println("IP:  Identification = " +identification);
        System.out.println("IP:  Flags = 0x"+flag);

        String message = "";

        if ((int)fragmentBit1 == 1){
            message = "do not fragment";
        } else {
            message = "last fragment";
        }
        System.out.println("IP:      ."+(int)fragmentBit1+".. .... = " +message );


        if ((int)fragmentBit2 == 1){
            message = "do not fragment";
        } else {
            message = "last fragment";
        }

        System.out.println("IP:      .."+(int)fragmentBit2+". .... = " +message );

        System.out.println("IP:  Fragment offset = "+fragmentOffset);
        System.out.println("IP:  Time to live = " +timeToLive+" seconds/hops");
        System.out.println("IP:  Protocol = "+protocol);
        System.out.println("IP:  Header checksum = 0x" +headerChecksum);
        System.out.println("IP:  Source address = " +sourceAddress);
        System.out.println("IP:  Destination address = " +destinationAddress);
        if(headerLength == 20){
            System.out.println("IP:  No Options");
        } else {
            System.out.println("IP:  Options Present");
        }
        System.out.println("IP: ");
        System.out.println("IP:");

        return protocol;
    }

    public static void processTcpFlags(byte[] flagBytes){
        byte urgentPointerBit = (byte)(flagBytes[0]>>5 & 1);
        byte acknowledgementBit = (byte)(flagBytes[0]>>4 & 1);
        byte pushBit = (byte)(flagBytes[0]>>3 & 1);
        byte resetBit = (byte)(flagBytes[0] >>2 &1);
        byte synBit = (byte)(flagBytes[0] >>1 &1);
        byte finBit = (byte)(flagBytes[0] &1);

        String message="";
        if((int)urgentPointerBit==1){
            message = "Urgent pointer";
        } else if ((int)urgentPointerBit==0){
            message = "No urgent pointer";
        }

        System.out.println("TCP:       .."+(int)urgentPointerBit+". .... = " +message);

        message="";
        if((int)acknowledgementBit==1){
            message = "Acknowledgement";
        } else if ((int)urgentPointerBit==0){
            message = "No acknowledgement";
        }

        System.out.println("TCP:       ..."+(int)acknowledgementBit+" .... = " +message);

        message="";
        if((int)pushBit==1){
            message = "Push";
        } else if ((int)pushBit==0){
            message = "No push";
        }

        System.out.println("TCP:       .... "+(int)pushBit+"... = " +message);


        message="";
        if((int)resetBit==1){
            message = "Reset";
        } else if ((int)resetBit==0){
            message = "No reset";
        }

        System.out.println("TCP:       .... ."+(int)resetBit+"... = " +message);

        message="";
        if((int)synBit==1){
            message = "Syn";
        } else if ((int)synBit==0){
            message = "No syn";
        }

        System.out.println("TCP:       .... .."+(int)synBit+".. = " +message);

        message="";
        if((int)finBit==1){
            message = "Fin";
        } else if ((int)finBit==0){
            message = "No fin";
        }

        System.out.println("TCP:       .... ..."+(int)finBit+" = " +message);

    }

    public static void processTcp(){
        byte[] sourcePortBytes = readBytes(2);
        byte[] destinationPortBytes = readBytes(2);
        byte[] sequenceNumberBytes = readBytes(4);
        byte[] acknowledgementNumberBytes = readBytes(4);
        byte[] dataOffsetBytes = readBytes(1);
        byte[] flagBytes = readBytes(1);
        byte[] windowSizeBytes = readBytes(2);
        byte[] checksumBytes = readBytes(2);
        byte[] urgentPointer = readBytes(2);

        String sourcePortHex = convertToHex(sourcePortBytes);
        String destinationPortHex = convertToHex(destinationPortBytes);
        String sequenceNumberHex = convertToHex(sequenceNumberBytes);
        String acknowledgementNumberHex = convertToHex(acknowledgementNumberBytes);
        String windowSizeHex = convertToHex(windowSizeBytes);
        String checksum = convertToHex(checksumBytes);
        String urgentPointerHex = convertToHex(urgentPointer);
//        String dataOffsetValue = convertToHex(dataOffsetBytes);

        long sourcePort = hexToDecimal(sourcePortHex);
        long destinationPort = hexToDecimal(destinationPortHex);
        long sequenceNumber = hexToDecimal(sequenceNumberHex);
        long acknowledgementNumber = hexToDecimal(acknowledgementNumberHex);
        long windowSize = hexToDecimal(windowSizeHex);
        long urgentPointerValue = hexToDecimal(urgentPointerHex);
//        long dataOffset = hexToDecimal(dataOffsetValue);

        System.out.println("TCP:  -----TCP Header -----");
        System.out.println("TCP:");

        System.out.println("TCP:  Source Port             = " + sourcePort);
        System.out.println("TCP:  Destination Port        = " + destinationPort);
        System.out.println("TCP:  Sequence Number         = " + sequenceNumber);
        System.out.println("TCP:  Acknowledgement Number  = " + acknowledgementNumber);
//        System.out.println("TCP:  Data offset             = " +dataOffset);


        String flag = convertToHex(flagBytes);
        System.out.println("TCP:  Flag                    = 0x" +flag);
        processTcpFlags(flagBytes);

        System.out.println("TCP:  Window  = " + windowSize);
        System.out.println("TCP:  Checksum  = 0x" +checksum);
        System.out.println("TCP:  Urgent Pointer = "+urgentPointerValue);
        //OPTIONS
        System.out.println("TCP:");
    }

    public static void processUdp(){
        byte[] sourcePortBytes = readBytes(2);
        byte[] destinationPortBytes = readBytes(2);
        byte[] lengthBytes = readBytes(2);
        byte[] checksumBytes = readBytes(2);

        String sourcePortHex = convertToHex(sourcePortBytes);
        String destinationPortHex = convertToHex(destinationPortBytes);
        String lengthHex = convertToHex(lengthBytes);
        String checksum = convertToHex(checksumBytes);

        long sourcePort = hexToDecimal(sourcePortHex);
        long destinationPort = hexToDecimal(destinationPortHex);
        long length = hexToDecimal(lengthHex);

        System.out.println("UDP:  -----UDP Header-----");
        System.out.println("UDP:");

        System.out.println("UDP:  Source Port             = " + sourcePort);
        System.out.println("UDP:  Destination Port        = " + destinationPort);
        System.out.println("UDP:  Length                  = " + length);
        System.out.println("UDP:  Checksum                = 0x" + checksum);
        System.out.println("UDP:");
    }

    public static void processIcmp(){

        byte[] typeBytes = readBytes(1);
        byte[] codeBytes = readBytes(1);
        byte[] checksumBytes = readBytes(2);

        String typeHex = convertToHex(typeBytes);
        String codeHex = convertToHex(codeBytes);
        String checksum = convertToHex(checksumBytes);

        long type = hexToDecimal(typeHex);
        long code = hexToDecimal(codeHex);

        System.out.println("ICMP:  -----ICMP Header-----");
        System.out.println("ICMP:");

        System.out.println("ICMP:  Type =   " +type);
        System.out.println("ICMP:  Code = " +code);
        System.out.println("ICMP:  Checksum = 0x" +checksum);
        System.out.println("ICMP:");
    }

    public static void main(String[] args) throws Exception {
        String fileName = "";
        for (String s: args){
            fileName = s;
        }
        File file = new File("/Users/poornimasapkal/Documents/Fall 2019/Foundations of Computer Networks/Project1/"+fileName);
        fin = new FileInputStream(file);
        int packetSize = fin.available();
        processEther(packetSize);
        long protocol = processIp();
        System.out.println(protocol);

        if(protocol == 1){
            processIcmp();
        } else if (protocol == 6){
            processTcp();
            processDataBytes(protocol);
        } else if (protocol == 17){
            processUdp();
            processDataBytes(protocol);
        }

    }
}
