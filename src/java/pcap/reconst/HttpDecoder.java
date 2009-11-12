package pcap.reconst;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import pcap.reconst.beans.*;
import pcap.reconst.compression.CompressionType;
import pcap.reconst.decoder.Decoder;
import pcap.reconst.decoder.DecoderFactory;
import pcap.reconst.output.Http;
import pcap.reconst.output.HttpDecodedOutput;
import pcap.reconst.output.HttpOutput;

import java.util.HashMap;
import java.util.Map;

public class HttpDecoder {
    private static Logger log = Logger.getLogger(HttpDecoder.class);

    private Map<TcpConnection, HttpOutput> httpPackets;
    private Decoder decoder = DecoderFactory.getDecoder();

    public HttpDecoder(Map<TcpConnection, HttpOutput> httpPackets) {
        this.httpPackets = httpPackets;
    }

    public Map<TcpConnection, HttpDecodedOutput> decodeResponse() {
        Map<TcpConnection, HttpDecodedOutput> decodedOutput = new HashMap<TcpConnection, HttpDecodedOutput>();
        for (TcpConnection tcpConnection : httpPackets.keySet()) {
            HttpOutput httpOutput = httpPackets.get(tcpConnection);
            HttpDecodedOutput output = decode(httpOutput);
            decodedOutput.put(tcpConnection, output);
        }
        return decodedOutput;
    }

    private HttpDecodedOutput decode(HttpOutput httpOutput) {
        HttpDecodedOutput httpDecodedOutput = new HttpDecodedOutput(httpOutput);
        InputData response = httpOutput.getResponse();
        DecodedData decodedResponse = new DecodedData(response);
        try {
            decodedResponse = decodeInput(response);
        } catch (Exception e) {
            e.printStackTrace();
        }
        httpDecodedOutput.setDecodedResponse(decodedResponse);
        log.debug(">>>>>>>>>>> decoded response");
        log.debug(decodedResponse.toString());
        return httpDecodedOutput;
    }

    private DecodedData decodeInput(InputData input) {
        DecodedData output = decoder.decode(input.getData(), input.getHeaders());
        log.debug(output);
        return output;
    }

}
