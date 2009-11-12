package pcap.reconst.reconstructor;

import junit.framework.Assert;
import org.junit.Before;
import org.junit.Test;
import pcap.reconst.beans.TcpConnection;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;

public class TcpConnectionTest {
    byte ONE = Byte.parseByte("11");
    byte TWO = Byte.parseByte("22");
    byte SIX = Byte.parseByte("66");
    InetAddress onedotonedotonedotone;
    InetAddress twodottwodottwodottwo;
    InetAddress sixdotsixdotsixdotsix;

    TcpConnection oneToTwo;
    TcpConnection twoToOne;
    TcpConnection oneToSix;

    @Before
    public void setup() throws UnknownHostException {
        onedotonedotonedotone = InetAddress.getByAddress(new byte[] { ONE, ONE, ONE, ONE });
        twodottwodottwodottwo = InetAddress.getByAddress(new byte[] { TWO, TWO, TWO, TWO });
        sixdotsixdotsixdotsix = InetAddress.getByAddress(new byte[] { SIX, SIX, SIX, SIX });

        oneToTwo = new TcpConnection(onedotonedotonedotone, (short) 1, twodottwodottwodottwo, (short) 2);
        twoToOne = new TcpConnection(twodottwodottwodottwo, (short) 2, onedotonedotonedotone, (short) 1);
        oneToSix = new TcpConnection(onedotonedotonedotone, (short) 1, sixdotsixdotsixdotsix, (short) 6);
    }

    @Test
    public void equals() {
        Assert.assertEquals(oneToTwo, oneToTwo);
        Assert.assertEquals(twoToOne, twoToOne);
        Assert.assertEquals(oneToTwo, twoToOne);
        Assert.assertEquals(twoToOne, oneToTwo);
    }

    @Test
    public void notEquals() {
        Assert.assertFalse(oneToTwo == oneToSix);
        Assert.assertFalse(oneToSix == oneToTwo);
        Assert.assertFalse(oneToSix == twoToOne);
        Assert.assertFalse(twoToOne == oneToSix);
    }

    @Test
    public void setLookup() {
        Set<TcpConnection> set = new HashSet<TcpConnection>();
        set.add(oneToTwo);
        set.add(oneToSix);
        Assert.assertTrue(set.contains(twoToOne));

        set = new HashSet<TcpConnection>();
        set.add(twoToOne);
        set.add(oneToSix);
        Assert.assertTrue(set.contains(oneToTwo));
    }
}
