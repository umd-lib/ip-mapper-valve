package edu.umd.lib.tomcat.ipvalves;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Properties;

import javax.servlet.ServletException;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.MessageBytes;

public class IPAddressMapper extends ValveBase {

  protected static final String info = "edu.umd.lib.tomcat.ipvalves.IPAddressMapper/0.0.1";

  private static final Log log = LogFactory.getLog(IPAddressMapper.class);

  private String mappingFile;
  private String headerName;

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
   * @note I'm a bit confused if this is necessary. Couldn't there be multiple
   *       header names based on where a user fits into one or more IP blocks?
   */
  public void setHeaderName(String headerName) {
    this.headerName = headerName;
  }

  @Override
  public void invoke(Request request, Response response) throws IOException, ServletException {

    /**
     * General TODOs
     *
     * @TODO Determine development environment (cargo, tomcat, etc?)
     * @TODO Get complete list of IPs (later)
     * @TODO Determine application structure
     */

    /**
     * Attempt to load our properties file
     *
     * @TODO Test
     */
    Properties properties = new Properties();
    InputStream input = null;

    try {
      input = new FileInputStream(this.mappingFile);
      properties.load(input);
    } catch (IOException e) {
      e.printStackTrace();
      log.error(e);
      // No reason to go beyond this point.
      getNext().invoke(request, response);
    } finally {
      if (input != null) {
        try {
          input.close();
        } catch (IOException ex) {
          ex.printStackTrace();
        }
      }
    }

    /**
     * Check user headers for existing header. This is necessary to prevent
     * spoofing. If the header already exists, strip and reevaluate.
     *
     * @TODO Strip if exists *done*
     * @TODO Log alert if exists *done*
     * @TODO Test
     */
    MessageBytes storedHeader = request.getCoyoteRequest().getMimeHeaders().getValue(this.headerName);
    if (storedHeader != null) {
      log.warn("Header: " + storedHeader + " found before IP mapper eval!");
      request.getCoyoteRequest().getMimeHeaders().removeHeader(this.headerName);
    }

    /**
     * Get user IP. For now, we are assuming only IPV4.
     *
     * @TODO Get user IP
     * @TODO Test
     * @note Is proxy support needed?
     */
    String rawIP = request.getHeader("X-FORWARDED-FOR");
    String userIP = null;
    if (rawIP == null) {
      userIP = request.getRemoteAddr();
    } else {
      /**
       * It's possible we might get a comma-separated list of IPs, in which
       * case, we should split prior to evaluation. Real IP should always come
       * first. This doesn't look pretty though.
       */
      String[] userIPs = rawIP.split(",");
      if (userIPs[0] != null) {
        userIP = userIPs[0].trim();
      }
    }

    /**
     * Compare user IP to properties blocks.
     *
     * @TODO Find a good IP comparison library *done*
     * @TODO Write comparison logic. It must support CIDR *done*
     * @TODO Loop through properties data *done*
     * @TODO Test
     */
    Enumeration<?> propertyNames = properties.propertyNames();

    ArrayList<String> approvals = new ArrayList<String>();
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
        utils = new SubnetUtils(subnet);
        if (utils.getInfo().isInRange(userIP)) {
          approvals.add(key);
        }
      }
    }

    /**
     * Inject the header with value if the user's IP meets the above criteria.
     *
     * @TODO Determine what happens if the criteria doesn't match (nothing?)
     * @TODO Write header injection
     * @TODO Test
     */
    if (!approvals.isEmpty()) {
      // MessageBytes newHeader =
      // request.getCoyoteRequest().getMimeHeaders().addValue(this.headerName);
      // newHeader.setString(value);
    }

    getNext().invoke(request, response);
  }

}
