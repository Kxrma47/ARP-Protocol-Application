package org.example;

import org.pcap4j.core.*;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.*;

public class ARPSniffer {

    private static final int SNAPLEN = 65536;
    private static final int TIMEOUT = 30000;

    private static final PcapNetworkInterface.PromiscuousMode MODE = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

    private static final ConcurrentHashMap<String, Set<String>> ipToMacMap = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Set<String>> macToIpMap = new ConcurrentHashMap<>();
    private static final Set<String> uniqueMacAddresses = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private static final Set<String> uniqueIpAddresses = Collections.newSetFromMap(new ConcurrentHashMap<>());

    private static int arpRequests = 0;
    private static int arpResponses = 0;
    private static int ethernetFrames = 0;
    private static int arpFrames = 0;
    private static long dataVolume = 0;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Select a mode:\n1 - Capture ARP Packets\n2 - Analyze ARP Traffic for a period\n3 - Detect Duplicate IP (Gratuitous ARP)\n4 - Exit");

        int choice = scanner.nextInt();
        switch (choice) {
            case 1 -> captureARP();
            case 2 -> {
                System.out.print("Enter capture duration (seconds): ");
                int duration = scanner.nextInt();
                analyzeARP(duration);
            }
            case 3 -> detectDuplicateIP();
            case 4 -> System.exit(0);
            default -> System.out.println("Invalid choice.");
        }
    }
    private static void captureARP() {
        try {
            // List all interfaces
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            interfaces.forEach(iface -> System.out.println("Interface: " + iface.getName()));

            // Pick the correct interface (for example, "en0")
            PcapNetworkInterface nif = Pcaps.getDevByName("en5"); // Updated to en0
            if (nif == null) {
                System.err.println("No suitable network interface found.");
                return;
            }

            // Open the handle with filter for ARP
            PcapHandle handle = nif.openLive(SNAPLEN, MODE, TIMEOUT);
            handle.setFilter("arp", BpfProgram.BpfCompileMode.OPTIMIZE); // ARP filter
            System.out.println("Listening for ARP packets...");

            long startTime = System.currentTimeMillis();
            while ((System.currentTimeMillis() - startTime) < 60000) {  // Capture for 60 seconds
                Packet packet = handle.getNextPacketEx();
                ethernetFrames++;
                dataVolume += packet.length();

                ArpPacket arpPacket = packet.get(ArpPacket.class);
                if (arpPacket != null) {
                    arpFrames++;
                    analyzeArpPacket(arpPacket);
                }
            }

        } catch (Exception e) {
            System.err.println("Error capturing ARP packets:");
            e.printStackTrace(); // Print full stack trace
        }
    }


    private static void analyzeArpPacket(ArpPacket arpPacket) {
        String senderMac = arpPacket.getHeader().getSrcHardwareAddr().toString();
        String senderIp = arpPacket.getHeader().getSrcProtocolAddr().toString().substring(1); // Remove leading "/"
        String targetMac = arpPacket.getHeader().getDstHardwareAddr().toString();
        String targetIp = arpPacket.getHeader().getDstProtocolAddr().toString().substring(1); // Remove leading "/"

        String operation = arpPacket.getHeader().getOperation().valueAsString();
        String arpType = operation.equals("1") ? "Request" : "Response";

        // Update sets/maps concurrently
        uniqueMacAddresses.add(senderMac);
        uniqueMacAddresses.add(targetMac);
        uniqueIpAddresses.add(senderIp);
        uniqueIpAddresses.add(targetIp);

        ipToMacMap.computeIfAbsent(senderIp, k -> new HashSet<>()).add(senderMac);
        macToIpMap.computeIfAbsent(senderMac, k -> new HashSet<>()).add(senderIp);

        if (operation.equals("1")) {
            arpRequests++;
        } else {
            arpResponses++;
        }

        // Print ARP packet details
        System.out.println("\nDetected ARP " + arpType + " packet:");
        System.out.println("Sender MAC: " + senderMac);
        System.out.println("Sender IP: " + senderIp);
        System.out.println("Target MAC: " + targetMac);
        System.out.println("Target IP: " + targetIp);
    }

    private static void analyzeARP(int duration) {
        System.out.println("Analyzing ARP traffic for " + duration + " seconds...");
        long startTime = System.currentTimeMillis();

        while ((System.currentTimeMillis() - startTime) < duration * 1000) {
            captureARP();
        }

        System.out.println("\n---- ARP Traffic Analysis ----");
        System.out.println("Total ARP Requests: " + arpRequests);
        System.out.println("Total ARP Responses: " + arpResponses);
        System.out.println("Unique MAC Addresses: " + uniqueMacAddresses.size());
        System.out.println("Unique IP Addresses: " + uniqueIpAddresses.size());
        System.out.println("IP linked to multiple MACs: " + countMultipleMappings(ipToMacMap));
        System.out.println("MAC linked to multiple IPs: " + countMultipleMappings(macToIpMap));
        System.out.println("Total Ethernet Frames: " + ethernetFrames);
        System.out.println("ARP Frames: " + arpFrames);
        System.out.println("Data Volume: " + dataVolume + " bytes");
    }

    private static int countMultipleMappings(Map<String, Set<String>> map) {
        int count = 0;
        for (Set<String> values : map.values()) {
            if (values.size() > 1) {
                count++;
            }
        }
        return count;
    }

    private static void detectDuplicateIP() {
        try {
            InetAddress localAddress = InetAddress.getLocalHost();
            PcapNetworkInterface nif = Pcaps.getDevByAddress(localAddress);
            if (nif == null) {
                System.err.println("No suitable network interface found.");
                return;
            }

            PcapHandle handle = nif.openLive(SNAPLEN, MODE, TIMEOUT);
            System.out.println("Checking for duplicate IPs...");

            while (true) {
                Packet packet = handle.getNextPacketEx();
                ArpPacket arpPacket = packet.get(ArpPacket.class);

                if (arpPacket != null) {
                    String senderIp = arpPacket.getHeader().getSrcProtocolAddr().toString().substring(1);  // Remove leading "/"
                    if (senderIp.equals(localAddress.getHostAddress())) {
                        System.out.println("WARNING: Possible IP conflict detected! Another device is using your IP.");
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error detecting duplicate IPs: " + e.getMessage());
        }
    }
}
