# lldp

This repo contains a daemon that acts as both sending and receiving agent for
LLDP and a CLI utility to manage that daemon.  The primary goal for the daemon
is to run in an `omicron` switch zone, advertising the presence and identity of
the corresponding Sidecar switch, and to collect information about the network
to which the Sidecar is connected.  The daemon may also be used in any non-Oxide
`illumos` or `linux` installation.

## Building

To build the daemon and the CLI, run `cargo build`.  The daemon will be `lldpd`
and the CLI will be `lldpadm`.

### Features

There are two features that may be enabled when building the daemon.

- `smf`: Enabling this feature will cause the daemon to query the `illumos`
  `smf` facility for a Sidecar-specific set of configuration settings:
    - `config/address`: the set of addresses on which the daemon should listen for OpenAPI connections.
    - `config/scrimlet_id`: the serial number of the scrimlet hosting the switch zone.  This name is used to construct the default `chassis_id` property.
    - `config/scrimlet_model`: the version of the scrimlet on which the switch zone is running.  This model number is incorporated into the default `system_description` property.
    - `config/board_rev`: the version of the Sidecar being managed by the scrimlet.  This version number is incorporated into the default `system_description` property.
- `dendrite`: Enabling this property is needed to allow the daemon to operate correctly in the switch zone.  With this set, the daemon will interact with `dpd` to gather information about the ports being managed on the Sidecar switch.

## Packaging and installing

For testing, the daemon and CLI may be run by hand directly from the `target`
directory.  The two binaries can also be packaged for installation.

`cargo xtask dist` will cause two binaries to be packaged in the "native"
format for the system it is run on.

### Illumos

On `illumos`, `cargo xtask dist` will give you a `p5p` package that may be
installed with the `pkg` utility.  When the package is installed, it will
include an SMF manifest allowing the daemon to be managed via `smf`.  Note: this
is independent of the `smf` feature.  If the feature is not enabled, the
daemon's lifecycle may still be managed with `smf`, but it will not query the
`smf` database for configuration information.

```
nonesuch$ pfexec pkg install -g ./lldp.p5p pkg://oxide/system/lldp
           Packages to install:  1
       Create boot environment: No
Create backup boot environment: No

DOWNLOAD                                PKGS         FILES    XFER (MB)   SPEED
Completed                                1/1           4/4    76.8/76.8  379M/s

PHASE                                          ITEMS
Installing new actions                         13/13
Updating package state database                 Done
Updating package cache                           0/0
Updating image state                            Done
Creating fast lookup database                   Done
Reading search index                            Done
Updating search index                            1/1
Updating package cache                           2/2
nonesuch$ pfexec svccfg import /lib/svc/manifest/system/lldpd.xml
nonesuch$ pfexec svcadm enable lldpd
nonesuch$ svcs lldpd
STATE          STIME    FMRI
online         15:33:31 svc:/oxide/lldpd:default
```

To package the daemon and CLI in a format suitable for integrating into the
`omicron` install system, run `cargo xtask dist --format omicron`.

### Linux

On `linux`, `cargo xtask dist` will give you a `.deb` package that can be
installed with `dpkg`.  There is not (yet?) any integration with `systemd`, so
the daemon will still need to be started by hand.  The daemon and CLI can both
be found in `/opt/oxide/bin`.

## Configuration

The daemon's configuration is managed with `lldpadm`.   Interaces can be added,
removed, and queried with the `iface` command:

```
nonesuch$ lldpadm iface add ixgbe0
nonesuch$ lldpadm iface get ixgbe0
port: ixgbe0 interface: ixgbe0
        ChassisID: ChassisComponent("rust")
        PortId: InterfaceName("ixgbe0")
        TTL:  120 seconds
        System Name: i86pc
        System Description: SunOS rust 5.11 helios-2.0.22467 i86pc i386 i86pc
        Capabilities Available: [Router]
        Capabilities Enabled: [Router]
nonesuch$ lldpadm iface del ixgbe0
nonesuch$
```

This configuration primarily takes place via the setting of "properties".
Broadly speaking, there are two levels of properties: system-wide and per-port.
These properties affect the frequency and contents of the advertisements issued
on each port.

There are three properties that must always be set, as they correspond to the
mandatory fields in each `LLDP` advertisment: `chassis_id`, `port_id`, and
`TTL`.  At startup the daemon will establish default values for these properties
from `uname` (for daemons without the `smf` feature) or from the `smf`
configuration.
