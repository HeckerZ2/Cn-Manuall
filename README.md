[21:48, 04/12/2024] .: Common UDP Program
Server Program

import java.net.*;
import java.io.*;

public class UDPServer {
    public static void main(String[] args) {
        try {
            // Create server socket
            DatagramSocket serverSocket = new DatagramSocket(5000);
            System.out.println("Server is running and waiting for client messages...");

            byte[] receiveBuffer = new byte[1024];
            byte[] sendBuffer;

            while (true) {
                // Receive packet
                DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                serverSocket.receive(receivePacket);
                String clientMessage = new String(receivePacket.getData(), 0, receivePacket.getLength());
                System.out.println("Client: " + clientMessage);

                if ("exit".equalsIgnoreCase(clientMessage)) {
                    System.out.println("Connection closed by client.");
                    break;
                }

                // Prepare and send response
                String serverResponse = "Server received: " + clientMessage;
                sendBuffer = serverResponse.getBytes();
                InetAddress clientAddress = receivePacket.getAddress();
                int clientPort = receivePacket.getPort();
                DatagramPacket sendPacket = new DatagramPacket(sendBuffer, sendBuffer.length, clientAddress, clientPort);
                serverSocket.send(sendPacket);
            }

            // Close server socket
            serverSocket.close();
        } catch (IOException e) {
            System.out.println("Server error: " + e.getMessage());
        }
    }
}

Client Program

import java.net.*;
import java.io.*;

public class UDPClient {
    public static void main(String[] args) {
        try {
            // Create client socket
            DatagramSocket clientSocket = new DatagramSocket();
            InetAddress serverAddress = InetAddress.getByName("localhost");

            byte[] sendBuffer;
            byte[] receiveBuffer = new byte[1024];
            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));

            while (true) {
                // Get user input and send it to the server
                System.out.print("Enter message (type 'exit' to quit): ");
                String messageToSend = userInput.readLine();
                sendBuffer = messageToSend.getBytes();
                DatagramPacket sendPacket = new DatagramPacket(sendBuffer, sendBuffer.length, serverAddress, 5000);
                clientSocket.send(sendPacket);

                if ("exit".equalsIgnoreCase(messageToSend)) {
                    System.out.println("Connection closed.");
                    break;
                }

                // Receive response from the server
                DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                clientSocket.receive(receivePacket);
                String serverResponse = new String(receivePacket.getData(), 0, receivePacket.getLength());
                System.out.println("Server: " + serverResponse);
            }

            // Close client socket
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("Client error: " + e.getMessage());
        }
    }
}

Explanation

    Server: Listens for messages from clients, processes them, and sends back a response.
    Client: Sends messages to the server and displays the server's response
[21:51, 04/12/2024] .: Common TCP Program
Server Program

import java.io.*;
import java.net.*;

public class TCPServer {
    public static void main(String[] args) {
        try {
            // Create server socket
            ServerSocket serverSocket = new ServerSocket(5000);
            System.out.println("Server is running and waiting for client connection...");

            // Accept client connection
            Socket socket = serverSocket.accept();
            System.out.println("Client connected!");

            // Input and Output streams
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // Communication loop
            String clientMessage;
            while ((clientMessage = in.readLine()) != null) {
                System.out.println("Client: " + clientMessage);
                // Send response to the client
                out.println("Server received: " + clientMessage);
                if ("exit".equalsIgnoreCase(clientMessage)) {
                    System.out.println("Connection closed by client.");
                    break;
                }
            }

            // Close connections
            in.close();
            out.close();
            socket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println("Server error: " + e.getMessage());
        }
    }
}

Client Program

import java.io.*;
import java.net.*;

public class TCPClient {
    public static void main(String[] args) {
        try {
            // Connect to the server
            Socket socket = new Socket("localhost", 5000);
            System.out.println("Connected to the server!");

            // Input and Output streams
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));

            // Communication loop
            String messageToSend;
            while (true) {
                System.out.print("Enter message (type 'exit' to quit): ");
                messageToSend = userInput.readLine();
                out.println(messageToSend);
                if ("exit".equalsIgnoreCase(messageToSend)) {
                    System.out.println("Connection closed.");
                    break;
                }
                // Receive server response
                System.out.println("Server: " + in.readLine());
            }

            // Close connections
            userInput.close();
            in.close();
            out.close();
            socket.close();
        } catch (IOException e) {
            System.out.println("Client error: " + e.getMessage());
        }
    }
}
[21:59, 04/12/2024] .: Common for ARP Protocols
Client:
java
Copy code
import java.io.*;
import java.net.*;

class Clientarp {
    public static void main(String args[]) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            Socket clsct = new Socket("127.0.0.1", 139);
            DataInputStream din = new DataInputStream(clsct.getInputStream());
            DataOutputStream dout = new DataOutputStream(clsct.getOutputStream());

            System.out.print("Enter the Logical address (IP): ");
            String str1 = in.readLine();
            dout.writeBytes(str1 + "\n");

            String str = din.readLine();
            System.out.println("The Physical Address is: " + str);

            clsct.close();
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
Server
java
Copy code
import java.io.*;
import java.net.*;

class Serverarp {
    public static void main(String args[]) {
        try {
            ServerSocket server = new ServerSocket(139);
            System.out.println("Server is running...");
            Socket socket = server.accept();
            DataInputStream din = new DataInputStream(socket.getInputStream());
            DataOutputStream dout = new DataOutputStream(socket.getOutputStream());

            String[] ip = {"165.165.80.80", "165.165.79.1"};
            String[] mac = {"6A:08:AA:C2", "8A:BC:E3:FA"};

            while (true) {
                String clientIP = din.readLine();
                boolean found = false;
                for (int i = 0; i < ip.length; i++) {
                    if (clientIP.equals(ip[i])) {
                        dout.writeBytes(mac[i] + "\n");
                        found = true;
                        break;
                    }
                }
                if (!found) dout.writeBytes("MAC Address not found\n");
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
[22:03, 04/12/2024] .: Common for Error Detection and CRC:
import java.io.*;

class CRCGenerator {
    public static void main(String[] args) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

        // Input data and divisor
        System.out.print("Enter number of data bits: ");
        int dataBits = Integer.parseInt(br.readLine());
        int[] data = new int[dataBits];
        System.out.println("Enter data bits: ");
        for (int i = 0; i < dataBits; i++) data[i] = Integer.parseInt(br.readLine());

        System.out.print("Enter number of divisor bits: ");
        int divisorBits = Integer.parseInt(br.readLine());
        int[] divisor = new int[divisorBits];
        System.out.println("Enter divisor bits: ");
        for (int i = 0; i < divisorBits; i++) divisor[i] = Integer.parseInt(br.readLine());

        int totalLength = dataBits + divisorBits - 1;
        int[] dividend = new int[totalLength];
        int[] remainder = new int[totalLength];
        int[] crc = new int[totalLength];

        System.arraycopy(data, 0, dividend, 0, dataBits);

        // Calculate CRC
        remainder = divide(dividend, divisor, remainder);
        for (int i = 0; i < totalLength; i++) crc[i] = dividend[i] ^ remainder[i];

        System.out.println("CRC code: ");
        for (int bit : crc) System.out.print(bit);
        System.out.println();

        // Error detection
        System.out.println("Enter received CRC code: ");
        for (int i = 0; i < totalLength; i++) crc[i] = Integer.parseInt(br.readLine());

        remainder = divide(crc, divisor, remainder);
        boolean error = false;
        for (int bit : remainder) if (bit != 0) { error = true; break; }

        System.out.println(error ? "Error detected" : "No error detected");
    }

    static int[] divide(int[] dividend, int[] divisor, int[] remainder) {
        int cur = 0;
        while (true) {
            for (int i = 0; i < divisor.length; i++) 
                remainder[cur + i] ^= divisor[i];
            while (cur < remainder.length && remainder[cur] == 0) 
                cur++;
            if (remainder.length - cur < divisor.length) break;
        }
        return remainder;
    }
}
[22:05, 04/12/2024] .: Common for Distance or Path :
Here is the Distance Vector Routing Protocol code without the # comments at the beginning of each line:

tcl
Copy code
set ns [new Simulator]
$ns rtproto DV
set nf [open out.nam w]
$ns namtrace-all $nf
set nt [open trace.tr w]
$ns trace-all $nt
proc finish {}
{
global ns nf
$ns flush-trace
close $nf
exec nam -a out.nam &
exit 0
}
set n1 [$ns node]
set n2 [$ns node]
set n3 [$ns node]
set n4 [$ns node]
set n5 [$ns node]
set n6 [$ns node]
set n7 [$ns node]
set n8 [$ns node]
$ns duplex-link $n1 $n2 1Mb 10ms DropTail
$ns duplex-link $n2 $n3 1Mb 10ms DropTail
$ns duplex-link $n3 $n4 1Mb 10ms DropTail
$ns duplex-link $n4 $n5 1Mb 10ms DropTail
$ns duplex-link $n5 $n6 1Mb 10ms DropTail
$ns duplex-link $n6 $n7 1Mb 10ms DropTail
$ns duplex-link $n7 $n8 1Mb 10ms DropTail
$ns duplex-link $n8 $n1 1Mb 10ms DropTail
$ns duplex-link-op $n1 $n2 orient left-up
$ns duplex-link-op $n2 $n3 orient up
$ns duplex-link-op $n3 $n4 orient right-up
$ns duplex-link-op $n4 $n5 orient right
$ns duplex-link-op $n5 $n6 orient right-down
$ns duplex-link-op $n6 $n7 orient down
$ns duplex-link-op $n7 $n8 orient left-down
$ns duplex-link-op $n8 $n1 orient left
set udp0 [new Agent/UDP]
$ns attach-agent $n1 $udp0
set cbr0 [new Application/Traffic/CBR]
$cbr0 set packetSize_ 500
$cbr0 set interval_ 0.005
$cbr0 attach-agent $udp0
set null0 [new Agent/Null]
$ns attach-agent $n4 $null0
$ns connect $udp0 $null0
$ns at 0.0 "$n1 label Source"
$ns at 0.0 "$n4 label Destination"
$ns at 0.5 "$cbr0 start"
$ns rtmodel-at 1.0 down $n3 $n4
$ns rtmodel-at 2.0 up $n3 $n4
$ns at 4.5 "$cbr0 stop"
$ns at 5.0 "finish"
$ns run
[22:13, 04/12/2024] .: Common for performance analysis :
# Create Simulator
set ns [new Simulator]
$ns color 0 Blue
$ns color 1 Red
$ns color 2 Yellow

# Open trace and NAM files
set traceFile [open combined.tr w]
$ns trace-all $traceFile
set namFile [open combined.nam w]
$ns namtrace-all $namFile

# Node creation
set n0 [$ns node]
set n1 [$ns node]
set n2 [$ns node]
set n3 [$ns node]
set n4 [$ns node]
set n5 [$ns node]

# Link configuration
$ns duplex-link $n0 $n2 5Mb 2ms DropTail
$ns duplex-link $n1 $n2 5Mb 2ms DropTail
$ns duplex-link $n2 $n3 1.5Mb 10ms DropTail
$ns duplex-link $n1 $n4 0.3Mb 10ms DropTail
$ns duplex-link $n4 $n5 0.5Mb 10ms DropTail

# TCP Section
set tcp [new Agent/TCP]
set sink [new Agent/TCPSink]
$ns attach-agent $n1 $tcp
$ns attach-agent $n3 $sink
$ns connect $tcp $sink
set ftp [new Application/FTP]
$ftp attach-agent $tcp
$ns at 1.0 "$ftp start"

# UDP Section
set udp [new Agent/UDP]
set cbr [new Application/Traffic/CBR]
$cbr attach-agent $udp
set null [new Agent/Null]
$ns attach-agent $n0 $udp
$ns attach-agent $n1 $null
$ns connect $udp $null
$ns at 2.0 "$cbr start"

# Routing Section
$ns rtproto DV
$ns rtmodel-at 3.0 down $n1 $n4
$ns rtmodel-at 5.0 up $n1 $n4

# Finish Procedure
proc finish {} {
    global ns traceFile namFile
    $ns flush-trace
    close $traceFile
    close $namFile
    exec nam combined.nam &
    exit 0
}

# End simulation
$ns at 6.0 "finish"
$ns run
[22:15, 04/12/2024] .: Congestion Control:
#include <wifi_lte/wifi_lte_rtable.h>

void DCCPTFRCAgent::removeAcksRecvHistory() {
    struct r_hist_entry *elm1 = STAILQ_FIRST(&r_hist_);
    struct r_hist_entry *elm2;
    int num_later = 1;

    // Traverse history until reaching the threshold
    while (elm1 != NULL && num_later++ <= num_dup_acks_) {
        elm1 = STAILQ_NEXT(elm1, linfo_);
    }
    if (elm1 == NULL) return;

    elm2 = STAILQ_NEXT(elm1, linfo_);
    while (elm2 != NULL) {
        if (elm2->type_ == DCCP_ACK) {
            STAILQ_REMOVE(&r_hist_, elm2, r_hist_entry, linfo_);
            delete elm2;
        } else {
            elm1 = elm2;
        }
        elm2 = STAILQ_NEXT(elm1, linfo_);
    }
}

inline r_hist_entry* DCCPTFRCAgent::findDataPacketInRecvHistory(r_hist_entry *start) {
    while (start != NULL && start->type_ == DCCP_ACK) {
        start = STAILQ_NEXT(start, linfo_);
    }
    return start;
}

void processRecvHistory() {
    struct r_hist_entry *elm = STAILQ_FIRST(&r_hist_), *elm2;
    int num_later = 1;

    // Traverse to the packet after duplicate ACKs
    while (elm != NULL && num_later++ <= num_dup_acks_) {
        elm = STAILQ_NEXT(elm, linfo_);
    }
    if (elm != NULL) {
        elm = findDataPacketInRecvHistory(STAILQ_NEXT(elm, linfo_));
        if (elm != NULL) {
            elm2 = STAILQ_NEXT(elm, linfo_);
            while (elm2 != NULL) {
                if (elm2->seq_num_ < seq_num && elm2->t_recv_ < time) {
                    STAILQ_REMOVE(&r_hist_, elm2, r_hist_entry, linfo_);
                    delete elm2;
                } else {
                    elm = elm2;
                }
                elm2 = STAILQ_NEXT(elm, linfo_);
            }
        }
    }
}
[22:19, 04/12/2024] .: Common C Progroam:

C: Client Program (hello_client.c)
c
Copy code
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE] = "Hello, world!";
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    recvfrom(sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
    printf("Message received: %s\n", buffer);
    close(sock);
    return 0;
}
Java: Server Program (HelloServer.java)
java
Copy code
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class HelloServer {
    public static void main(String[] args) {
        try (DatagramSocket serverSocket = new DatagramSocket(8080)) {
            byte[] receiveBuffer = new byte[1024];
            DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
            serverSocket.receive(receivePacket);
            System.out.println("Client says: " + new String(receivePacket.getData(), 0, receivePacket.getLength()));

            String response = "Hello from server!";
            serverSocket.send(new DatagramPacket(response.getBytes(), response.length(),
                receivePacket.getAddress(), receivePacket.getPort()));
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
[22:21, 04/12/2024] .: 5th Question :

a) Use of Network Configuration Commands
i) tcpdump

Unix: tcpdump is a command-line network packet analyzer used to capture and analyze network traffic. It is commonly used to monitor traffic on a network interface in real-time, to debug network issues, or to analyze network protocols.
Windows: tcpdump can also be used on Windows through tools like Cygwin or WinDump. It functions similarly to its Unix counterpart for capturing and analyzing network packets.
ii) netstat

Unix: netstat is a command-line tool for displaying network connections, routing tables, and network interface statistics. It is commonly used to identify open ports, established connections, and their status.
Windows: On Windows, netstat provides similar functionality to show active connections, listening ports, and routing tables. It's used for network troubleshooting and to detect malicious or unusual connections.
iii) ifconfig / ipconfig

Unix: ifconfig is used to configure or display network interface parameters on Unix-like systems. It shows details about network interfaces like IP addresses, MAC addresses, and interface status.
Windows: ipconfig is the equivalent command on Windows systems. It displays network interface configurations, including IP address, subnet mask, and default gateway. It is commonly used to troubleshoot network connectivity issues.
iv) nslookup

Unix: nslookup is a command-line tool used to query Domain Name System (DNS) to obtain domain name or IP address mapping. It is useful for DNS troubleshooting and verifying domain name resolutions.
Windows: nslookup works the same on Windows and is used to query DNS servers for information about domain names, such as their corresponding IP addresses or reverse lookups.
v) traceroute

Unix: traceroute is a network diagnostic tool that shows the path packets take to reach a remote host. It helps in identifying network delays or failures by showing the sequence of hops between the source and destination.
Windows: On Windows, the tracert command is used instead of traceroute. It works in the same way to trace the route and measure the time taken to reach a destination.
b) Capturing FTP Username and Password Using Wireshark
Wireshark is a powerful network protocol analyzer that captures packets and displays the data sent over a network. To capture FTP (File Transfer Protocol) username and password, you would follow these general steps:

Start Wireshark:

Open Wireshark and select the network interface on which you want to capture traffic (e.g., Ethernet or Wi-Fi).
Set the capture filter (optional):

If you only want to capture FTP traffic, set a filter like tcp port 21. This will capture all packets related to FTP (since FTP typically uses port 21).
Capture the traffic:

Start capturing the packets by clicking on the "Start" button in Wireshark.
Login to the FTP server:

From a client (e.g., using an FTP client or command line), log in to the FTP server with your username and password. Wireshark will capture the network packets exchanged during this session.
Analyze the FTP login:

Stop the capture after logging in and filter the captured packets by looking for USER and PASS commands, which are used to send the FTP username and password respectively.
You can filter the packets with ftp.request.command == "USER" or ftp.request.command == "PASS".
In the packet details, the FTP username and password will be visible in plain text, as FTP transmits credentials without encryption.
Note: Capturing FTP credentials in this manner is only possible if the FTP connection is unencrypted (FTP, not FTPS or SFTP). If encryption is used (like FTPS or SFTP), the credentials would not be visible in plaintext.
