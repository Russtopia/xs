# XS
An alternative to ssh (&lt;5% SLOCC) written from scratch in Go. Testbed for post-quantum cryptography KEMs (Key-Encapsulation Mechanisms) and symmetric session encryption algos. Traffic chaffing to obscure session activity. Linux, FreeBSD, Windows (MSYS), Android (Termux).

## I no longer host (new) projects on Github, preferring self-hosted solutions. See https://gogs.blitter.com/RLabs/xs to learn more about this project.
---


XS (**X**perimental **S**hell) is a simple alternative to ssh (<5% total SLOCC) written from scratch in Go.
A testbed for candidate PQC (Post-Quantum Cryptography) KEMs (Key-Encapsulation Mechanisms) and symmetric
session encryption algorithms.

xs also features integrated traffic chaffing to obscure interactive session and file copy activity.
Supports encrypted interactive and non-interactive sessions (remote commands), remote file copying and tunnels.

Runs on Linux, FreeBSD, Windows (client only, MSYS) and Android (within Termux). https://gogs.blitter.com/RLabs/xs

It is stable to the point that I use it for day-to-day remote access in place of, and in preference to, ssh.

***
**NOTE: Due to the experimental nature of the KEX/KEM algorithms used, and the novelty of the overall codebase, this package SHOULD BE CONSIDERED EXTREMELY EXPERIMENTAL and USED WITH CAUTION. It DEFINITELY SHOULD NOT be used for any sensitive applications. USE AT YOUR OWN RISK. NEITHER WARRANTY NOR CLAIM OF FITNESS FOR PURPOSE IS EXPRESSED OR IMPLIED.**

***

The client and server programs (xs and xsd) use a mostly drop-in
replacement for golang's standard golang/pkg/net facilities (net.Dial(), net.Listen(), net.Accept()
and the net.Conn type), which automatically negotiate keying material for
secure sockets using one of a selectable set of experimental key exchange (KEX) or
key encapsulation mechanisms (KEM).

### Key Exchange
Currently supported exchanges are:

* The HerraduraKEx key exchange algorithm first released at
[Omar Elejandro Herrera Reyna's HerraduraKEx project](http://github.com/Caume/HerraduraKEx);
* The KYBER IND-CCA-2 secure key encapsulation mechanism, [pq-crystals Kyber](https://pq-crystals.org/kyber/)  :: [Yawning/kyber golang implementation](https://gitlab.com/yawning/kyber)
* The NEWHOPE algorithm [newhopecrypto.org](https://www.newhopecrypto.org/) :: [Yawning/newhope golang implementation](https://gitlab.com/yawning/newhope)
* The FrodoKEM algorithm [frodokem.org](https://frodokem.org/) :: Go version by [Eduardo E. S. Riccardi](https://github.com/kuking/go-frodokem)

Currently supported session algorithms:

[Encryption]
* AES-256
* Twofish-128
* Blowfish-64
* CryptMTv1 (64bit) (https://eprint.iacr.org/2005/165.pdf)
* ChaCha20 (https://github.com/aead/chacha20)

[HMAC]
* HMAC-SHA256
* HMAC-SHA512

***
**A Note on 'cryptographic agility'**

It has been suggested recently to me that offering multiple cryptographic primitives is considered bad in 2021.

An interesting question. See [this write-up for a discussion](https://paragonie.com/blog/2019/10/against-agility-in-cryptography-protocols).

xs operates via the philosophy that **it is the server admin's prerogitive to configure local policy wrt. allowed cryptographic primitives**. The connection protocol makes no allowance for any sort of 'downgrades' or algo substitution during negotiation; there is no 'fallback' mode or two-way negotiation of what primitives to use, which would open the possibility of downgrade attacks. Unlike `ssh`, the server does not offer to clients a list of supported algorithms; the client can only offer a single configuration to the server, which it simply accepts or rejects without comment to the client.

In all releases prior to v0.9.3, absent a specific whitelist of algs to allow, the server allows 'all' combinations of the above cryptographic primitives to be proposed by clients (but again, **only one** combination is proposed by the client in a single connect attempt). If the admin wishes to restrict the accepted algorithms now or at any future time, they may use the `-aK`, `-aC` and `-aH` options when launching the server to define a whitelist which excludes certain primitives.

As of release v0.9.3, the default when supplying no explicit KEX, cipher or HMAC algorithms to `xsd` results in *no* algs being accepted; so the admin must decide on a specific whitelist of algorithms.
***


### Conn
Calls to xsnet.Dial() and xsnet.Listen()/Accept() are generally the same as calls to the equivalents within the _net_ package; however upon connection a key exchange automatically occurs whereby client and server independently derive the same keying material, and all following traffic is secured by a symmetric encryption algorithm.

### Session Negotiation
Above the xsnet.Conn layer, the server and client apps in this repository (xsd/ and xs/ respectively) negotiate session settings (cipher/hmac algorithms, interactive/non-interactive mode, tunnel specifiers, etc.) to be used for communication.

### Padding and Chaffing
Packets are subject to padding (random size, randomly applied as prefix or postfix), and optionally the client and server channels can both send _chaff_ packets at random defineable intervals to help thwart analysis of session activity (applicable to interactive and non-interactive command sessions, file copies and tunnels).

### Mux/Demux of Chaffing and Tunnel Data
Chaffing and tunnels, if specified, are set up during initial client->server connection. Packets from the client local port(s) are sent through the main secured connection to the server's remote port(s), and vice versa, tagged with a chaff or tunnel specifier so that they can be discarded as chaff or de-multiplexed and delivered to the proper tunnel endpoints, respectively.

### Accounts and Passwords
Within the ```xspasswd/``` directory is a password-setting utility, ```xspasswd```, used if one wishes ```xs``` access to use separate credentials from those of the default (likely ssh) login method. In this mode, ```xsd``` uses its own password file distinct from the system /etc/passwd to authenticate clients, using standard bcrypt+salt storage. Activate this mode by invoking ```xsd``` with ```-s false```.

HERRADURA KEX

As of this time (Oct 2018) no verdict by acknowledged 'crypto experts' as to
the level of security of the HerraduraKEx algorithm for purposes of session
key exchange over an insecure channel has been rendered.
It is hoped that experts in the field will analyze the algorithm and
determine if it is indeed a suitable one for use in situations where
Diffie-Hellman or other key exchange algorithms are currently utilized.

KYBER IND-CCA-2 KEM

As of this time (Oct 2018) Kyber is one of the candidate algorithms submitted to the [NIST post-quantum cryptography project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography). The authors recommend using it in "... so-called hybrid mode in combination with established "pre-quantum" security; for example in combination with elliptic-curve Diffie-Hellman." THIS PROJECT DOES NOT DO THIS (in case you didn't notice yet, THIS PROJECT IS EXPERIMENTAL.)

### Dependencies:

* Recent version of go (tested, at various times, with go-1.9 to go-1.12.4)
* [github.com/mattn/go-isatty](http://github.com/mattn/go-isatty) //terminal tty detection
* [github.com/kr/pty](http://github.com/kr/pty) //unix pty control (server pty connections)
* [github.com/jameskeane/bcrypt](http://github.com/jameskeane/bcrypt) //password storage/auth
* [blitter.com/go/goutmp](https://gogs.blitter.com/RLabs/goutmp) // wtmp/lastlog C bindings for user accounting
* [https://gitlab.com/yawning/kyber](https://gogs.blitter.com/RLabs/kyber) // golang Kyber KEM
* [https://gitlab.com/yawning/kyber](https://gogs.blitter.com/RLabs/newhope) // golang NEWHOPE,NEWHOPE-SIMPLE KEX
* [blitter.com/go/mtwist](https://gogs.blitter.com/RLabs/mtwist) // 64-bit Mersenne Twister PRNG
* [blitter.com/go/cryptmt](https://gogs.blitter.com/RLabs/cryptmt) // CryptMTv1 stream cipher


### Installing

As of Go 1.8, one can directly use `go install` to get the client `xs` and server `xsd` binaries; however it is not recommended, as `xsd` requires root and for general use should be in one of the system directories, akin to other daemons. If one insists, the following will work to place them in $HOME/go/bin:

```
$ go install blitter.com/go/xs/xs@latest
$ go install blitter.com/go/xs/xsd@latest
```

(NOTE the `-v` (version) option for binaries obtained in this manner will be blank; another reason to build them yourself locally using the steps below.)


### Get source code

```
$ git clone https://gogs.blitter.com/RLabs/xs
```


### To build

```
$ cd xs
$ make clean && make
```

### To install, uninstall, re-install (xsd server)

```
$ sudo make [install | uninstall | reinstall]
```

### To manage service (openrc init)

An example init script (xsd.initrc) is provided. Consult your Linux distribution documentation for proper service/daemon installation. For openrc,

```
$ sudo cp xsd.initrc /etc/init.d/xsd
$ sudo rc-config add xsd default
```

### To manage service (sysV init)

An example init script (xsd.sysvrc) is provided. Consult your Linux distribution documentation for proper service/daemon installation. For sysV init,

```
$ sudo cp xsd.sysvrc /etc/init.d/xsd
$ sudo sysv-rc-conf --level 2345 xsd on
```

The make system assumes installation in /usr/local/sbin (xsd, xspasswd) and /usr/local/bin (xs/xc symlink).

```
$ sudo rc-config [start | restart | stop] xsd
# .. or sudo /etc/init.d/xsd [start | restart stop]
```

### To set accounts & passwords (DEPRECATED: `-s` is now true by default)

```
$ sudo touch /etc/xs.passwd
$ sudo xspasswd/xspasswd -u joebloggs
$ <enter a password, enter again to confirm>
```

### Testing Client and Server from $GOPATH dev tree (w/o 'make install')

In separate shells A and B:
```
[A]$ cd xsd && sudo ./xsd &  # add -d for debugging
```

Interactive shell
```
[B]$ cd xs && ./xs joebloggs@host-or-ip # add -d for debugging
```

One-shot command
```
[B]$ cd xs && ./xs -x "ls /tmp" joebloggs@host-or-ip
```

WARNING WARNING WARNING: the -d debug flag will echo passwords to the log/console!
Logging on Linux usually goes to /var/log/syslog and/or /var/log/debug, /var/log/daemon.log.

NOTE if running client (xs) with -d, one will likely need to run 'reset' afterwards
to fix up the shell tty afterwards, as stty echo may not be restored if client crashes
or is interrupted.

### Setting up an 'authtoken' for scripted (password-free) logins

Use the -g option of xs to request a token from the remote server, which will return a
hostname:token string. Place this string into $HOME/.xs_id to allow logins without
entering a password (obviously, $HOME/.xs_id on both server and client for the user
should *not* be world-readable.)

```
$ xs -g user@host.net >~/.xs_id
```
[enter password blindly, authtoken entry will be stored in ~/.xs_id]


### File Copying using xc

xc is a symlink to xs, and the binary checks its own filename to determine whether
it is being invoked in 'shell' or 'copy' mode. Refer to the '-h' output for differences in
accepted options.

General remote syntax is: user@server:[/]src-or-dest-path
If no leading / is specified in src-or-dest-path, it is assumed to be relative to $HOME of the
remote user. File operations are all performed as the remote user, so account permissions apply
as expected.

Local (client) to remote (server) copy:
```
$ xc fileA /some/where/fileB /some/where/else/dirC joebloggs@host-or-ip:remoteDir
```

Remote (server) to local (client) copy:
```
$ xc joebloggs@host-or-ip:/remoteDirOrFile /some/where/local/Dir
```

xc uses a 'tarpipe' to send file data over the encrypted channel. Use the -d flag on client or server to see the generated tar commands if you're curious.

NOTE: Renaming while copying (eg., 'cp /foo/bar/fileA ./fileB') is NOT supported. Put another way, the destination (whether local or remote) must ALWAYS be a directory.

If the 'pv' pipeview utility is available (http://www.ivarch.com/programs/pv.shtml) file transfer progress and bandwidth control will be available (suppress the former with the -q option, set the latter with -L &lt;bytes_per_second&gt;).

Special care should be taken when doing client → server copies: since the tarpipe (should) always succeed at least sending data to the remote side, a destination with no write permission will not return a nonzero status and the client closes its end after sending all data, giving the server no opportunity to send an error code to the client.
It is recommended to test beforehand if the server-side destination is writable (and optionally if the destination already exists, if one does not want to clobber an existing path) by:

```
$ xs -x "test -w /dest/path" me@myserver  ## If clobbering /dest/path is OK, or
$ xs -x "test -w /dest/path -o ! -e /dest/path" me@myserver  ## To prevent clobbering
```

Perhaps in future a more complex handshake will be devised to allow the client to half-close the tarpipe, allowing the server to complete its side of the operation and send back its success or failure code, but the current connection protocol does not allow this. If this is a deal-breaking feature, please contact the maintainer.

### Tunnels

Simple tunnels (client → server, no reverse tunnels for now) are supported.

Syntax: xs -T=&lt;tunspec&gt;{,&lt;tunspec&gt;...}
.. where &lt;tunspec&gt; is &lt;localport:remoteport&gt;

Example, tunnelling ssh through xs

* [server side] ```$ sudo /usr/sbin/sshd -p 7002```
* [client side, term A] ```$ xs -T=6002:7002 user@server```
* [client side, term B] ```$ ssh user@localhost -p 6002```


### Building for FreeBSD

The Makefile(s) to build require GNU make (gmake).
Please install and invoke build via:
```$ gmake clean all```
