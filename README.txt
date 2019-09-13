This is a program that reads a set of packets and produces a detailed summary of the headers that are present in the packet. 

The files present that are required to run this program are as follows: 
*packetReader.java

Compile and Execute:

1. Navigate to the folder where the above file is present. Make sure all the packet files that you want to run are present in the same directory. 

2. Open the command line interface and cd into the directory where all the files are present. Compile the file using the following command:- 

	javac <filename>
Eg. 	javac packetReader.java 

3. Run packetReader using the following command:-

	java packetReader <filename>
Eg.	java packetReader new_tcp_packet1.bin

// Here, the filename is the name of the binary file which contains information about the packet. 
