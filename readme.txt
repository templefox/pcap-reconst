There are three Java implementations for pcap

1. Jpcap - http://netresearch.ics.uci.edu/kfujii/jpcap/doc/index.html
2. Jpcap - http://jpcap.sourceforge.net/
3. JNetPcap - http://jnetpcap.com/

This project has implementations for Jpcap (#1).
The sourceforge hosted Jpcap, where used, is referred to as jpcap-sf.

For a working example refer to FileDataReconstructor. This uses Jpcap (#1). This analyzes and reconstructs the http packets in dump.pcap file.

The reconstruction code was implemented by referring to the wireshark source (related source files in src/wireshark) and by referring to the .NET "TCP Session Reconstruction Tool" (http://www.codeproject.com/KB/IP/TcpRecon.aspx)

To run the FileDataReconstructor jpcap.dll from #1 should be copied and should be in the PATH. 
