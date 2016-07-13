package edu.umd.lib.tomcat.ipvalves;

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
 * propertyName1=propertyValue1
 *
 * The valve expects the following configuration format and options:
 *
 * &lt;Valve className="edu.umd.lib.tomcat.valves.IPAddressMapper"
 * mappingFile="path/to/mapping.properties" headerName="Some-Header" /&gt;
 *
 * Note the following parameters: mappingFile and headerName.
 *
 * @author jgottwig
 */

public class IPAddressMapper extends ValveBase implements Lifecycle {

  protected static final String info = "edu.umd.lib.tomcat.ipvalves.IPAddressMapper/0.0.1";

  private static final Log log = LogFactory.getLog(IPAddressMapper.class);

  private String mappingFile;
  private String headerName;

  private Properties properties = new Properties();

  @Override
  protected void initInternal() throws LifecycleException {
    super.initInternal();
    if (checkProperties() || loadProperties()) {
      log.warn("IPProperties: Not found");
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
   * @param mappingFile
   * @note Could auth headers be comma-separated based on the properites keys?
   */
  public void setMappingFile(String mappingFile) {
    this.mappingFile = mappingFile;
  }

  /**
   * Get the header name we want to check/set for access
   *
   * @param headerName
   * @note Couldn't there be multiple header values based on where a user fits
   *       into one or more IP blocks?
   */
  public void setHeaderName(String headerName) {
    this.headerName = headerName;
  }

  /**
   * Check for valid IP
   *
   * @param ip
   * @return boolean (valid IP)
   */
  protected boolean isValidIP(String ip) {
    log.info("IPVali: init");
    return InetAddressValidator.getInstance().isValidInet4Address(ip);
  }

  /**
   * Get user IP from the request
   *
   * @param request
   * @return String (userIP)
   */
  protected String retrieveIP(Request request) {
    String userIP = null;
    String rawIP = request.getHeader("X-FORWARDED-FOR");
    if (rawIP == null) {
      userIP = request.getRemoteAddr();
      log.info("IPNorm: " + userIP);
    } else {
      /**
       * It's possible we might get a comma-separated list of IPs, in which
       * case, we should split prior to evaluation. Real IP should always come
       * first. This doesn't look pretty though.
       */
      log.info("IPRaw: " + rawIP);
      String[] userIPs = rawIP.split(",");
      if (userIPs[0] != null) {
        userIP = userIPs[0].trim();
        log.info("IPProx: " + userIP);
      }
    }
    log.info("IPReturning: " + userIP);
    return userIP;
  }

  /**
   * Examine IP and compare against subnets from properties
   *
   * @param ip
   * @return List (approval strings)
   */
  protected List<String> getApprovals(String ip) {
    Enumeration<?> propertyNames = properties.propertyNames();

    List<String> approvals = new ArrayList<String>();
    log.info("IPBefore");
    SubnetUtils utils; // Our comparison library

    /**
     * Loop through properties. Check each IP block and compare with the user's
     * IP. If a match, add to our approvals ArrayList.
     */
    while (propertyNames.hasMoreElements()) {
      String key = (String) propertyNames.nextElement();
      String property = properties.getProperty(key);
      String[] subnets = property.split(",");
      for (String subnet : subnets) {
        log.info("IPip: " + subnet);
        utils = new SubnetUtils(subnet);
        log.info("IPAfter: " + utils);
        if (utils.getInfo().isInRange(ip)) {
          log.info("IPMatch");
          approvals.add(key);
        } else {
          log.info("IPNoMatch");
        }
      }
    }
    return approvals;
  }

  protected boolean checkProperties() {
    Enumeration<?> propertyNames = properties.elements();
    return propertyNames.hasMoreElements();
  }

  /**
   * Load the properties file
   *
   * @return boolean (success)
   */
  protected boolean loadProperties() {
    boolean success = false;
    log.info("IPProps: NoProps");
    InputStream input = null;
    try {
      input = new FileInputStream(mappingFile);
      properties.load(input);
      log.info("IPAddress: " + properties.getProperty("campus"));
      success = true;
    } catch (IOException e) {
      e.printStackTrace();
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

  @Override
  public void invoke(Request request, Response response) throws IOException, ServletException {

    log.info(request);
    log.info("IPMapping File: " + mappingFile);
    log.info("IPHeader Name: " + headerName);

    /**
     * Attempt to load our properties file
     *
     * @TODO Move this into some sort of cache method?
     * @TODO Look at lifecycle stuff
     * @TODO Test
     */
    if (checkProperties()) {

      /**
       * Check user headers for existing header. This is necessary to prevent
       * spoofing. If the header already exists, strip and reevaluate.
       *
       * @TODO Strip if exists *done*
       * @TODO Log alert if exists *done*
       * @TODO Test
       */
      MessageBytes storedHeader = request.getCoyoteRequest().getMimeHeaders().getValue(headerName);
      if (storedHeader != null) {
        log.warn("Header: " + storedHeader + " found before IP mapper eval!");
        request.getCoyoteRequest().getMimeHeaders().removeHeader(headerName);
      } else {
        log.info("IPHeader: Not found");
      }

      /**
       * Get user IP. For now, we are assuming only IPV4.
       *
       * @TODO Get user IP
       * @TODO Test
       * @note Is proxy support needed?
       */
      String userIP = retrieveIP(request);

      log.info("IPBreak");

      if (isValidIP(userIP)) {
        log.info("passed");
        /**
         * Compare user IP to properties IPs
         */
        List<String> approvals = getApprovals(userIP);

        /**
         * Inject the header with value if the user's IP meets the above
         * criteria.
         *
         * @TODO Determine what happens if the criteria doesn't match (nothing?)
         * @TODO Write header injection
         * @TODO Test
         */
        String finalHeaders = null;
        if (!approvals.isEmpty()) {
          finalHeaders = StringUtils.join(approvals, ",");
          log.info("IPNew: " + finalHeaders);
          request.getCoyoteRequest().getMimeHeaders().setValue(headerName).setString(finalHeaders);
        }
      } // @end validIP
    } // @end loadProperties
    log.info("IPHeader: " + request.getHeader(headerName));
    log.info("IPResponse: " + response.getHeader(headerName));
    log.info("IPTest: " + response.getHeader("Content-Type"));
    getNext().invoke(request, response); // Junit for testing
  }
}
