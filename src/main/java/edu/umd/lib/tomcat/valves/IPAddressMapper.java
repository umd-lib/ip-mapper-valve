package edu.umd.lib.tomcat.valves;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import javax.servlet.ServletException;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.MessageBytes;

/**
 * This valve checks a user's IP address against a properties file containing
 * one or more IP blocks. If the user's IP is found within one or more of these
 * blocks, the valve inserts a header, which can then be read by other
 * applications to determine access rights.
 *
 * The properties file should follow the following format:
 *
 * blockName=0.0.0.0/32,0.0.0.0/16
 *
 * The header value will be a comma-separated list of all of the blockNames
 * where the user's IP address matched the block's IP address(es).
 *
 * The valve expects the following configuration format and options:
 *
 * &lt;Valve className="edu.umd.lib.tomcat.valves.IPAddressMapper"
 * mappingFile="path/to/mapping.properties" headerName="Some-Header" /&gt;
 *
 * @author jgottwig
 */
public class IPAddressMapper extends ValveBase implements Lifecycle {

  private static final String info = "edu.umd.lib.tomcat.valves.IPAddressMapper/1.0.0";

  private static final Log log = LogFactory.getLog(IPAddressMapper.class);

  private String mappingFile;

  private String headerName;

  private Properties properties = new Properties();

  @Override
  protected void initInternal() throws LifecycleException {
    super.initInternal();
    if (!(checkProperties() || loadProperties())) {
      log.warn("Properties: Not found");
    }
  }

  /**
   * Constructor
   */
  public IPAddressMapper() {
    super(true);
  }

  @Override
  public String getInfo() {
    return (info);
  }

  /**
   * Get the file name to be referenced for the IP blocks This will be a
   * properties file
   *
   * @param mappingFile name of the properties file
   */
  public void setMappingFile(String mappingFile) {
    this.mappingFile = mappingFile;
  }

  /**
   * Get the header name we want to check/set for access
   *
   * @param headerName name of the header
   */
  public void setHeaderName(String headerName) {
    this.headerName = headerName;
  }

  /**
   * Check for valid IP address
   *
   * @param ip IP address to check
   * @return boolean (valid IP)
   */
  private boolean isValidIP(String ip) {
    return InetAddressValidator.getInstance().isValidInet4Address(ip);
  }

  /**
   * Examine IP and compare against subnets from properties.
   *
   * Check each IP block and compare with the user's
   * IP.
   *
   * @param ip IP address to check
   * @return List of block names that the user's IP address matches
   */
  private List<String> getApprovals(String ip) {
    Enumeration<?> propertyNames = properties.propertyNames();

    List<String> approvals = new ArrayList<>();

    while (propertyNames.hasMoreElements()) {
      String key = (String) propertyNames.nextElement();
      String property = properties.getProperty(key);
      String[] subnets = property.split(",");
      for (String subnet : subnets) {
        if (isValidIP(subnet)) {
          if (subnet.equals(ip)) {
            approvals.add(key);
          }
        } else {
          try {
            final SubnetUtils utils = new SubnetUtils(subnet);
            if (utils.getInfo().isInRange(ip)) {
              approvals.add(key);
            }
          } catch (Exception e) {
            log.warn("Subnet Error: " + e.getMessage());
          }
        }
      }
    }
    return approvals;
  }

  /**
   * Verify that we have something in our configuration file... Or that our
   * properties even loaded properly.
   *
   * @return boolean (result of .hasMoreElements())
   */
  private boolean checkProperties() {
    Enumeration<?> propertyNames = properties.elements();
    return propertyNames.hasMoreElements();
  }

  /**
   * Load the properties file
   *
   * @return boolean (success)
   */
  boolean loadProperties() {
    boolean success = false;
    InputStream input = null;
    try {
      input = new FileInputStream(mappingFile);
      properties.load(input);
      success = true;
    } catch (IOException e) {
      log.error(e);
    } finally {
      if (input != null) {
        try {
          input.close();
        } catch (IOException ex) {
          ex.printStackTrace();
        }
      }
    }
    return success;
  }

  /**
   * Check the user's IP address against the configured IP address blocks, and
   * add the names of any matching block to the configured header. Remove any
   * existing instances of that header, to prevent spoofing.
   * Compare user IP to properties IPs
   *
   * @param request incoming request
   * @param response outgoing response
   */
  @Override
  public void invoke(Request request, Response response) throws IOException, ServletException {

    // Check user headers for existing header. This is necessary to prevent spoofing.
    // If the header already exists, strip and reevaluate.
    MessageBytes storedHeader = request.getCoyoteRequest().getMimeHeaders().getValue(headerName);
    if (storedHeader != null) {
      log.warn("Header: " + storedHeader + " found before IP mapper eval!");
      request.getCoyoteRequest().getMimeHeaders().removeHeader(headerName);
    }

    String userIP = getUserIP(request);

    if (userIP != null && isValidIP(userIP)) {
      List<String> approvals = getApprovals(userIP);

      // Inject the header with value if the user's IP meets the above criteria.
      if (!approvals.isEmpty()) {
        final String finalHeaders = StringUtils.join(approvals, ",");
        MessageBytes newHeader = request.getCoyoteRequest().getMimeHeaders().setValue(headerName);
        newHeader.setString(finalHeaders);
        log.info("IP Mapper added: " + finalHeaders + " to header " + headerName + " for IP " + userIP);
      }
    } // @end isValidIP
    getNext().invoke(request, response);
  }

  /**
   * Get the user's IP.
   *
   * For now, we are assuming only IPV4. It's possible we might get a
   * comma-separated list of IPs, in which case, we should split prior to
   * evaluation. Real IP should always come first.
   *
   * @param request incoming request
   * @return the user's IP address, or null
   */
  private String getUserIP(Request request) {
    String rawIP = request.getHeader("X-FORWARDED-FOR");
    if (rawIP == null) {
      return request.getRemoteAddr();
    } else {
      String[] userIPs = rawIP.split(",");
      if (userIPs[0] != null) {
        return userIPs[0].trim();
      } else {
        return null;
      }
    }
  }
}