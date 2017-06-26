# About Stubby

Stubby is the name given to a mode of using [getdns](https://getdnsapi.net/) which enables it to act as a local **DNS Privacy stub resolver** (using DNS-over-TLS). Stubby encrypts DNS queries sent from a client machine (desktop or laptop) to a DNS Privacy resolver increasing end user privacy. Stubby is in the early stages of development but is suitable for technical/advanced users. A more generally user-friendly version is on the way!

In this mode Stubby (getdns) does several things

* Runs as a daemon
* By default obtains its configuration information from the configuration file at `/etc/stubby.conf`
* Can be configured to listen on the loopback address and send all outgoing DNS queries received on that address out over TLS to a DNS Privacy server
* Can be configured with authentication information for DNS Privacy servers and instructed to use either a 'Strict' or an 'Opportunistic' Profile as described in [Authentication and (D)TLS Profile for DNS-over-(D)TLS](https://datatracker.ietf.org/doc/draft-ietf-dprive-dtls-and-tls-profiles/)

Stubby is available in the 1.1 release of getdns.  

# Installing Using a Package Manager

Check to see if the 1.1 release of getdns is available via a package manager. Details on Supported Platforms can be found in the 'Supported Platforms' section of the [README](https://getdnsapi.net/documentation/readme)  documentation. 

Note: a Homebrew package for Stubby is on the way. 

# Building Stubby from Source

## Dependencies

For Stubby, the only dependency is OpenSSL (version 1.0.2 or later is required for hostname authentication to be supported). If OpenSSL is installed in a non-standard location on your system use the `--with-ssl` option to `configure` below to specify where it is installed.

### Linux

It may be necessary to install [1.0.2 from source](https://openssl.org/source/openssl-1.0.2h.tar.gz) for most Linux distros.

### OS X

It is recommended to [install OpenSSL using homebrew](http://brewformulas.org/Openssl), in which case use the following in the `configure` line in the build step below:

```sh
--with-ssl=/usr/local/opt/openssl/
```

## Download the getdns source

Either clone the code:

```sh
> git clone https://github.com/getdnsapi/getdns.git
> cd getdns
> git checkout develop
```
for the very latest version of getdns or grab a release tarball from this page: [Latest getdns releases](https://getdnsapi.net/releases/)

## Build the code

Note that on Mac OS X you will need the developer tools from Xcode to compile the code. And you may need to use brew to install libtool (and then use glibtoolize below), autoconf and automake.

```sh
> git submodule update --init
> libtoolize -ci
> autoreconf -fi
> mkdir build
> cd build
> ../configure --prefix=<install_location> --without-libidn --enable-stub-only --enable-debug-daemon
> make
> sudo make install
```

Logging/debugging

> **`--enable-debug-daemon`** If you don't want to see the connection statistics then remove the `--enable-debug-daemon` option in the `configure` line above.

> **`--enable-debug-stub`**   If you do want to see very detailed debug information as messages are processed (including connection statistics) then add the `--enable-debug-stub` option to the `configure` line above.

# Configure Stubby

!! <span class="glyphicon glyphicon-info-sign"></span> It is recommended to use the default configuration file provided which will use 'Strict' privacy mode and spread the DNS queries among several of the current DNS Privacy test servers. Note that this file contains both IPv4 and IPv6 addresses. To use this file simply run: <pre>> sudo cp ../src/tools/stubby.conf /etc/stubby.conf</pre>

Apologies, the config file was not included in the 1.1 release tarball, this will be fixed in the next release. The latest file can be downloaded from [here](https://github.com/getdnsapi/getdns/blob/develop/src/tools/stubby.conf).

### Create Custom Configuration File

Alternatively the configuration file location can be specified on the command line using the `-C` flag. Changes to the configuration file require a restart of Stubby.

The configuration file format is a JSON like format used internally in getdns and is the same as the output returned by `stubby -i`. For example, this output can be used as a configuration file directly, but a less verbose form is also accepted. Essentially the options available are the same as the options that can be set on a getdns `context` - Doxygen documentation for which is available [here](https://getdnsapi.net/doxygen/group__getdns__context.html). To aid with creating a custom configuration file, an example is given below. 

The config file below will configure Stubby in the following ways:

*  `resolution_type`: Work in stub mode only (not recursive mode) - required for Stubby operation.
*  `dns_transport_list`: Use TLS only as a transport (no fallback to UDP or TCP). 
*  `tls_authentication`:  Use Strict Privacy i.e. require a TLS connection and authentication of the upstream
  * If Opportunistic mode is desired, simply remove the `tls_authentication: GETDNS_AUTHENTICATION_REQUIRED` field. In Opportunistic mode authentication of the nameserver is not required and fallback to clear text transports is permitted if they are in the `dns_transport_list`.
*  `tls_query_padding_blocksize`: Use the EDNS0 padding option to pad DNS queries to hide their size
*  `edns_client_subnet_private`: Use EDNS0 Client Subnet privacy so the client subnet is not sent to authoritative servers
*  `listen_address`: have the Stubbby daemon listen on IPv4 and IPv6 on port 53 on the loopback address
* ` idle_timeout`:  Use an EDNS0 Keepalive idle timeout of 10s unless overridden by the server. This keeps idle TLS connections open to avoid the overhead of opening a new connection for every query.
*   `round_robin_upstreams`: Round robin queries across all the configured upstream servers. Without this option Stubby will use each upstream server sequentially until it becomes unavailable and then move on to use the next. 
*  `upstream_recursive_servers`: Use the NLnet labs test DNS Privacy Server for outgoing queries. In Strict Privacy mode, at least one of the following is required for each nameserver:
  *  `tls_auth_name`: This is the authentication domain name that will be verified against the presented certificate. 
  * `tls_pubkey_pinset`: The sha256 SPKI pinset for the server. This is also verified against the presented certificate. 

```
{ resolution_type: GETDNS_RESOLUTION_STUB
, dns_transport_list: [ GETDNS_TRANSPORT_TLS ]
, tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
, tls_query_padding_blocksize: 256
, edns_client_subnet_private : 1
, listen_addresses: [ 127.0.0.1, 0::1 ]
, idle_timeout: 10000
, round_robin_upstreams: 1
, upstream_recursive_servers:
  [ { address_data: 185.49.141.38
    , tls_auth_name: "getdnsapi.net"
    , tls_pubkey_pinset:
      [ { digest: "sha256"
        , value: foxZRnIh9gZpWnl+zEiKa0EJ2rdCGroMWm02gaxSc9Q=
      } ]
   } ]
}
```

Additional privacy servers can be specified by adding more entries to the `upstream_recursive_servers` list above (note a separate entry must be made for the IPv4 and IPv6 addresses of a given server. More DNS Privacy test servers are listed [here](https://portal.sinodun.com/wiki/display/TDNS/DNS-over-TLS+test+servers).

A custom port can be specified by adding the `tls_port:` attribute to the `upstream_recursive_server` in the config file. 


 
# Run Stubby


Simply invoke Stubby on the command line. By default it runs in the foreground, the `-g` flag runs it in the background. 

```sh
> sudo stubby
```

* The logging is currently crude and simply writes to stderr. (We are working on making this better!)
   * If don't want to see any logging for some reason then include the following on the command line: `2>/dev/null`
   * If you build with both stub and daemon logging and want to see only the daemon logging use: `2>&1 >/dev/null |  grep 'DAEMON' `
* The pid file is /var/run/stubby.pid

# Test Stubby

A quick test can be done by using dig (or your favourite DNS tool) on the loopback address

```sh
> dig @127.0.0.1 www.example.com
```

# Modify your upstream resolvers

!!! <span class="glyphicon glyphicon-warning-sign"></span> Once this change is made your DNS queries will be re-directed to Stubby and sent over TLS! <br>
(You may need to restart some applications to have them pick up the network settings). <p>You can monitor the traffic using Wireshark watching on port 853.</p>

For Stubby to re-send outgoing DNS queries over TLS the recursive resolvers configured on your machine must be changed to send all the local queries to the loopback interface on which Stubby is listening. This depends on the operating system being run. It is useful to note your existing default nameservers before making this change!


## Linux/Unix systems

* Edit the /etc/resolv.conf file
* Comment out the existing *nameserver* entries
* Add the following (only add the IPv4 address if you don't have IPv6)
  ```sh
  nameserver 127.0.0.1
  nameserver ::1
  ```

## OS X

From the command line you can do the following to set the local DNS servers on, for example, your 'Wi-Fi' interface (first line clears all servers, second line adds localhost):

```sh
> sudo networksetup -setdnsservers Wi-Fi Empty
> sudo networksetup -setdnsservers Wi-Fi 127.0.0.1 ::1
```

If you want to reset, just use:

```sh
> sudo networksetup -setdnsservers Wi-Fi Empty
```

which should pick up the default DHCP nameservers. Or use something similar to the first set of instructions if you want to specify particular namerservers.


Or via the GUI:

* Open *System Preferences &rarr; Network &rarr; Advanced &rarr; DNS*
* Use the '-' button to remove the existing nameservers
* Use the '+' button to add `127.0.0.1` and `::1` (only add the IPv4 address if you don't have IPv6)
* Hit 'OK' in the *DNS* pane and then 'Apply' on the *Network* pane


## Notes:

* If you are using a DNS Privacy server that does not support concurrent processing of TLS queries, you may experience some issues due to timeouts causing subsequent queries on the same connection to fail.

<p class="origin-reference">This post first appeared at <a href="https://portal.sinodun.com/wiki/display/TDNS/DNS+Privacy+daemon+-+Stubby">https://portal.sinodun.com/wiki/display/TDNS/DNS+Privacy+daemon+-+Stubby</a></p>

