# ip-mapper-valve

Request IP address to HTTP header mapping valve for Tomcat

## Usage

```xml
<Valve className="edu.umd.lib.tomcat.valves.IPAddressMapper"
  mappingFile="path/to/mapping.properties"
  headerName="Some-Header" />
```

The properties file keys are the principal names and the values are lists of one or more IP addresses or IP address blocks in CIDR notation (e.g., `192.168.0.0/24`).
