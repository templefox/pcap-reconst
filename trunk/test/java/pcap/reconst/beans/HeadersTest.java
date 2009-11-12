package pcap.reconst.beans;

import junit.framework.Assert;
import org.junit.Test;

public class HeadersTest {
    @Test
    public void hasHeader() {
        Headers headers = new Headers();
        headers.addHeader("foo", "bar");
        Assert.assertTrue(headers.hasHeader("foo"));
        Assert.assertFalse(headers.hasHeader("bar"));
    }

    @Test
    public void checkIfExistsWithNonEmptyValue() {
        Headers headers = new Headers();
        headers.addHeader("foo", "bar");
        headers.addHeader("foobar", "");
        headers.addHeader("foonull", null);
        Assert.assertTrue(headers.checkIfExistsWithNonEmptyValue("foo"));
        Assert.assertFalse(headers.checkIfExistsWithNonEmptyValue("bar"));
        Assert.assertFalse(headers.checkIfExistsWithNonEmptyValue("foobar"));
        Assert.assertFalse(headers.checkIfExistsWithNonEmptyValue("foonull"));
    }

    @Test
    public void getIfExistsWithNonEmptyValue() {
        Headers headers = new Headers();
        headers.addHeader("foo", "bar");
        headers.addHeader("foobar", "");
        headers.addHeader("foonull", null);
        Assert.assertEquals("bar", headers.getIfExistsWithNonEmptyValue("foo"));
        Assert.assertNull(headers.getIfExistsWithNonEmptyValue("bar"));
        Assert.assertNull(headers.getIfExistsWithNonEmptyValue("foobar"));
        Assert.assertNull(headers.getIfExistsWithNonEmptyValue("foonull"));
    }

}
