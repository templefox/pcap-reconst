package pcap.reconst.reconstructor;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.beans.TcpPacket;

import java.util.HashMap;
import java.util.Map;

public class PacketReassembler {

    private Map<TcpConnection, TcpReassembler> reassembledPackets;

    public PacketReassembler() {
        this.reassembledPackets = new HashMap<TcpConnection, TcpReassembler>();
    }

    public Map<TcpConnection, TcpReassembler> getReassembledPackets() {
        return reassembledPackets;
    }

    public void reassemble(TcpPacket tcpPacket) {
        try {
            // Creates a key for the dictionary
            TcpConnection c = new TcpConnection(tcpPacket);

            // create a new entry if the key does not exists
            if (!reassembledPackets.containsKey(c)) {
                TcpReassembler tcpReassembler = new TcpReassembler();
                reassembledPackets.put(c, tcpReassembler);
            }

            // Use the TcpRecon class to reconstruct the session
            reassembledPackets.get(c).reassemblePacket(tcpPacket);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
