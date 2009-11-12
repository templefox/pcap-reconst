package pcap.reconst.beans;

import pcap.reconst.Utils;

public class InputData {
    private byte[] data;
    private Headers headers;

    public InputData(byte[] data, Headers headers) {
        this.data = data;
        this.headers = headers;
    }

    public Headers getHeaders() {
        return headers;
    }

    public byte[] getData() {
        return data;
    }

    public int getInputLength() {
        return data.length;
    }

    public int getContentLength() {
        return headers.getContentLength();
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        if (headers != null) {
            builder.append("Headers...\n");
            for (String name : headers.getNames()) {
                builder.append(String.format("%s: %s\n", name, headers.getValue(name)));
            }
        }
        builder.append(String.format("Encoded string: %s\n", new String(data)));
        return builder.toString();
    }

    public void printHex() {
        Utils.prettyPrintHex(data);
    }
}