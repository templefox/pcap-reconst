package pcap.reconst.decoder;

import org.junit.Assert;
import org.junit.Test;
import pcap.reconst.Utils;
import pcap.reconst.beans.DecodedData;
import pcap.reconst.beans.Headers;

public class DecoderImplTest {

    @Test
    public void decodeGzip() {
        Decoder decoder = new DecoderImpl();
        byte[] input = Utils.getByteArray("quick.txt.gz");
        byte[] expectedOutput = Utils.getByteArray("quick.txt");

        Headers headers = new Headers();
        headers.addHeader(Headers.CONTENT_ENCODING, Headers.GZIP);
        DecodedData decodedData = decoder.decode(input, headers);
        byte[] outputData = decodedData.getData();
        Assert.assertArrayEquals(expectedOutput, outputData);
    }
}