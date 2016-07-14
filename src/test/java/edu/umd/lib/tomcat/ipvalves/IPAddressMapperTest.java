package edu.umd.lib.tomcat.ipvalves;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import javax.servlet.ServletException;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.junit.Before;
import org.junit.Test;

public class IPAddressMapperTest {

  private IPAddressMapper mapper;
  private InvokedValve invokedValve;
  private String headerName;
  private String mappingFile;

  @Before
  public void setUp() throws Exception {
    mapper = new IPAddressMapper();
    invokedValve = new InvokedValve();
    headerName = "some-header";
    mappingFile = "resources/testing.properties";

    mapper.setNext(invokedValve);
    mapper.setMappingFile(mappingFile);
    mapper.setHeaderName(headerName);
  }

  public static class MockRequest extends Request {
    @Override
    public void setAttribute(String name, Object value) {
      getCoyoteRequest().getAttributes().put(name, value);
    }

    @Override
    public Object getAttribute(String name) {
      return getCoyoteRequest().getAttribute(name);
    }
  }

  @Test
  public void testRemoteAddrNoStoredFalse() throws Exception {
    Request request = new MockRequest();
    request.setCoyoteRequest(new org.apache.coyote.Request());
    request.setRemoteAddr("193.168.39.1");
    mapper.invoke(request, null);
    boolean exists = request.getHeader(headerName) != null;
    assertFalse("Header " + headerName + " expected empty", exists);
  }

  @Test
  public void testRemoteAddrNoStoredTrue() throws Exception {
    Request request = new MockRequest();
    request.setCoyoteRequest(new org.apache.coyote.Request());
    request.setRemoteAddr("192.168.40.1");
    mapper.invoke(request, null);
    boolean exists = request.getHeader(headerName) != null;
    assertTrue("Header " + headerName + " expected filled", exists);
  }

  @Test
  public void testForwardedNoStoredTrue() throws Exception {
    Request request = new MockRequest();
    request.setCoyoteRequest(new org.apache.coyote.Request());
    request.getCoyoteRequest().getMimeHeaders().setValue("X-FORWARDED-FOR").setString("192.168.40.1");
    mapper.invoke(request, null);
    boolean exists = request.getHeader(headerName) != null;
    assertTrue("Header " + headerName + " expected filled", exists);
  }

  @Test
  public void testForwardedStoredFalse() throws Exception {
    Request request = new MockRequest();
    request.setCoyoteRequest(new org.apache.coyote.Request());
    request.getCoyoteRequest().getMimeHeaders().setValue("X-FORWARDED-FOR").setString("192.163.40.1");
    request.getCoyoteRequest().getMimeHeaders().setValue(headerName).setString("spoof-attempt");
    mapper.invoke(request, null);
    boolean exists = request.getHeader(headerName) != null;
    assertFalse("Header " + headerName + " expected empty", exists);
  }

  @Test
  public void testForwardedStoredTrue() throws Exception {
    Request request = new MockRequest();
    request.setCoyoteRequest(new org.apache.coyote.Request());
    request.getCoyoteRequest().getMimeHeaders().setValue("X-FORWARDED-FOR").setString("192.168.38.1");
    request.getCoyoteRequest().getMimeHeaders().setValue(headerName).setString("spoof-attempt");
    mapper.invoke(request, null);
    boolean exists = request.getHeader(headerName) != null;
    assertTrue("Header " + headerName + " expected filled", exists);
  }

  private class InvokedValve extends ValveBase {

    @Override
    public void invoke(Request testRequest, Response testResponse) throws IOException, ServletException {
      System.out.println("Proxy IP:" + testRequest.getHeader("X-FORWARDED-FOR"));
      System.out.println("Remote IP: " + testRequest.getRemoteAddr());
      System.out.println("Header: " + testRequest.getHeader(headerName));
    }
  }
}
