### Report on the ARP Protocol Application

#### **Introduction**
This report outlines the implementation and outcomes of the ARP Protocol application, which was developed using Java and the PCAP4J library. The purpose of this application is to interact with the ARP (Address Resolution Protocol) to capture, analyze, and process ARP packets in a network. The tasks include capturing ARP packets, analyzing network traffic, detecting duplicate IPs, and gathering statistics related to ARP traffic.

#### **Tasks and Implementation**

1. **Capture ARP Packets:**
   The application was designed to capture ARP requests and responses from the network using the `Pcap4J` library, which facilitates packet capture and analysis. The program was set to operate in promiscuous mode, allowing it to capture all packets transmitted over the network.

   **Code Output:**
   When the program was executed with the option to capture ARP packets, it successfully detected both ARP requests and responses. For instance:
   ```
   Detected ARP Request packet:
   Sender MAC: 18:fd:74:3c:06:1d
   Sender IP: 10.4.5.1
   Target MAC: 00:00:00:00:00:00
   Target IP: 10.4.5.37

   Detected ARP Response packet:
   Sender MAC: a0:ce:c8:fc:4f:18
   Sender IP: 10.4.5.37
   Target MAC: 18:fd:74:3c:06:1d
   Target IP: 10.4.5.1
   ```

2. **Analyze ARP Packets and Extract Information:**
   Upon capturing ARP packets, the program extracts key information including the sender's MAC address, sender IP, target MAC, and target IP. This helps in understanding the ARP communication taking place between devices.

   **Code Output:**
   For each ARP packet captured, the application correctly extracted the relevant information:
   ```
   Detected ARP Request packet:
   Sender MAC: 18:fd:74:3c:06:1d
   Sender IP: 10.4.5.1
   Target MAC: 00:00:00:00:00:00
   Target IP: 10.4.5.37
   ```

3. **ARP Traffic Analysis for a Period:**
   The application also allowed the user to analyze ARP traffic over a specified duration (e.g., 10 seconds). During this time, the program captured and analyzed ARP requests and responses, along with the associated statistics such as the number of ARP requests, ARP responses, unique MAC and IP addresses, and Ethernet frames.

   **Code Output:**
   The results of the analysis for a 10-second capture period are shown below:
   ```
   ---- ARP Traffic Analysis ----
   Total ARP Requests: 2
   Total ARP Responses: 1
   Unique MAC Addresses: 3
   Unique IP Addresses: 2
   IP linked to multiple MACs: 0
   MAC linked to multiple IPs: 0
   Total Ethernet Frames: 3
   ARP Frames: 3
   Data Volume: 162 bytes
   ```

4. **Detect Duplicate IP (Gratuitous ARP):**
   The program included a feature to detect duplicate IP addresses, which can occur when two devices on the same network claim to have the same IP address. This is often seen in Gratuitous ARP requests, which are sent to inform the network that a device's IP address has changed.

   **Code Output:**
   While monitoring for duplicate IPs, the application continuously checked incoming ARP packets and displayed a warning if a duplicate IP was detected:
   ```
   Checking for duplicate IPs...
   ```

5. **Data Volume and Ethernet Frames:**
   During the ARP traffic analysis, the program calculated the total volume of data transmitted in the network by summing the lengths of the captured packets. This feature provided insights into the overall data usage related to ARP traffic.

   **Code Output:**
   ```
   Data Volume: 162 bytes
   ```

6. **Investigating ARP Packet Structure:**
   ARP requests and responses follow a standard format in which an Ethernet frame encapsulates the ARP packet. The ARP packet contains details like the sender's MAC address, sender IP, target MAC address, and target IP. This structure is crucial for devices to map IP addresses to MAC addresses.

   **Example ARP Request and Response Structure:**
   The ARP Request packet from IP `10.4.5.1` to `10.4.5.37` looked like this:
   ```
   ARP Request from 10.4.5.1 to 10.4.5.37
   Sender MAC: 18:fd:74:3c:06:1d
   Target MAC: 00:00:00:00:00:00
   ```
