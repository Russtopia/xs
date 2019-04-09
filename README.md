[![GoDoc](https://godoc.org/blitter.com/go/hkexsh?status.svg)](https://godoc.org/blitter.com/go/hkexsh)


HKExSh
--

HKExSh (**H**erradura**K**yber**Ex** **Sh**ell) is a golang implementation of a simple
remote shell client and server, similar in role to ssh, offering
encrypted interactive and non-interactive sessions, file copying and tunnels with traffic obfuscation ('chaffing').

***
**NOTE: Due to the experimental nature of the KEX/KEM algorithms used, and the novelty of the overall codebase, this package SHOULD BE CONSIDERED EXTREMELY EXPERIMENTAL and USED WITH CAUTION. It DEFINITELY SHOULD NOT be used for any sensitive applications. USE AT YOUR OWN RISK. NEITHER WARRANTY NOR CLAIM OF FITNESS FOR PURPOSE IS EXPRESSED OR IMPLIED.**

***

The client and server programs (hkexsh and hkexshd) use a mostly drop-in
replacement for golang's standard golang/pkg/net facilities (net.Dial(), net.Listen(), net.Accept()
and the net.Conn type), which automatically negotiate keying material for
secure sockets using one of a selectable set of experimental key exchange (KEX) or
key encapsulation mechanisms (KEM).

Currently supported exchanges are:

* The HerraduraKEx key exchange algorithm first released at
[Omar Elejandro Herrera Reyna's HerraduraKEx project](http://github.com/Caume/HerraduraKEx);
* The KYBER IND-CCA-2 secure key encapsulation mechanism, [pq-crystals Kyber](https://pq-crystals.org/kyber/)  :: [Yawning/kyber golang implementation](https://git.schwanenlied.me/yawning/kyber)
* The NEWHOPE algorithm [newhopecrypto.org](https://www.newhopecrypto.org/) :: [Yawning/go-newhope golang implementation](https://git.schwanenlied.me/yawning/newhope)


Currently supported session algorithms:

[Encryption]
* AES-256
* Twofish-128
* Blowfish-64
* CryptMTv1 (64bit) (https://eprint.iacr.org/2005/165.pdf)

[HMAC]
* HMAC-SHA256
* HMAC-SHA512


Calls to hkexnet.Dial() and hkexnet.Listen()/Accept() are generally the same as calls to the equivalents within the _net_ package; however upon connection a key exchange automatically occurs whereby client and server independently derive the same keying material, and all following traffic is secured by a symmetric encryption algorithm.

Above the hkexnet.Conn layer, the server and client apps in this repository (hkexshd/ and hkexsh/ respectively) negotiate session settings (cipher/hmac algorithms, interactive/non-interactive, tunnels, if any, etc.) to be used for communication.

Packets are subject to random padding (size, prefix/postfix), and (optionally) the client and server
channels can both send _chaff_ packets at random defineable intervals to help thwart analysis of session activity (applicable to interactive and non-interactive command sessions, file copies and tunnels).

Tunnels, if specified, are set up during initial client->server connection. Packets from the client local port(s) are sent through the main secured connection to the server's remote port(s), and vice versa, tagged with a tunnel specifier so that they can be de-multiplexed and delivered to the proper tunnel endpoints.

Finally, within the hkexpasswd/ directory is a password-setting utility. HKExSh uses its own passwd file distinct from the system /etc/passwd to authenticate clients, using standard bcrypt+salt storage.


HERRADURA KEX

As of this time (Oct 2018) no verdict by acknowledged 'crypto experts' as to
the level of security of the HerraduraKEx algorithm for purposes of session
key exchange over an insecure channel has been rendered.
It is hoped that experts in the field will analyze the algorithm and
determine if it is indeed a suitable one for use in situations where
Diffie-Hellman or other key exchange algorithms are currently utilized.

KYBER IND-CCA-2 KEM

As of this time (Oct 2018) Kyber is one of the candidate algorithms submitted to the [NIST post-quantum cryptography project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography). The authors recommend using it in "... so-called hybrid mode in combination with established "pre-quantum" security; for example in combination with elliptic-curve Diffie-Hellman." THIS PROJECT DOES NOT DO THIS (in case you didn't notice yet, THIS PROJECT IS EXPERIMENTAL.)

Dependencies:
--
* Recent version of go (tested, at various times, with go-1.9 to go-1.11.1)
* [github.com/mattn/go-isatty](http://github.com/mattn/go-isatty) //terminal tty detection
* [github.com/kr/pty](http://github.com/kr/pty) //unix pty control (server pty connections)
* [github.com/jameskeane/bcrypt](http://github.com/jameskeane/bcrypt) //password storage/auth
* [blitter.com/go/goutmp](https://gogs.blitter.com/RLabs/goutmp) // wtmp/lastlog C bindings
* [https://git.schwanenlied.me/yawning/kyber](https://git.schwanenlied.me/yawning/kyber) // golang Kyber KEM
* [https://git.schwanenlied.me/yawning/newhope](https://git.schwanenlied.me/yawning/newhope) // golang NEWHOPE,NEWHOPE-SIMPLE KEX
* [blitter.com/go/mtwist](https://gogs.blitter.com/RLabs/mtwist) // 64-bit Mersenne Twister PRNG
* [blitter.com/go/cryptmt](https://gogs.blitter.com/RLabs/cryptmt) // CryptMTv1 stream cipher

Get source code
--
* $ go get -u blitter.com/go/hkexsh
* $ cd $GOPATH/src/blitter.com/go/hkexsh
* $ go build ./... # install all dependent go pkgs


To build
--
* $ cd $GOPATH/src/blitter.com/go/hkexsh
* $ make clean all

To install, uninstall, re-install
--
* $ sudo make [install | uninstall | reinstall]

To manage service (assuming openrc init)
--
* $ sudo rc-config [start | restart | stop] hkexshd


An example init script (hkexshd.initrc) is provided. Consult your Linux distribution documentation for proper service/daemon installation. Default assumes installation in /usr/local/sbin (hkexshd, hkexpasswd) and /usr/local/bin (hkexsh/hkexcp symlink).


To set accounts & passwords:
--
* $ sudo touch /etc/hkexsh.passwd
* $ sudo hkexpasswd/hkexpasswd -u joebloggs
* $ &lt;enter a password, enter again to confirm&gt;


Testing Client and Server from $GOPATH dev tree (w/o 'make install')
--
In separate shells A and B:
* [A]$ cd hkexshd && sudo ./hkexshd &  # add -d for debugging

Interactive shell
* [B]$ cd hkexsh && ./hkexsh joebloggs@host-or-ip # add -d for debugging

One-shot command
* [B]$ cd hkexsh && ./hkexsh -x "ls /tmp" joebloggs@host-or-ip

WARNING WARNING WARNING: the -d debug flag will echo passwords to the log/console!
Logging on Linux usually goes to /var/log/syslog and/or /var/log/debug, /var/log/daemon.log.

NOTE if running client (hkexsh) with -d, one will likely need to run 'reset' afterwards
to fix up the shell tty afterwards, as stty echo may not be restored if client crashes
or is interrupted.

Setting up an 'authtoken' for scripted (password-free) logins
--
Use the -g option of hkexsh to request a token from the remote server, which will return a
hostname:token string. Place this string into $HOME/.hkexsh_id to allow logins without
entering a password (obviously, $HOME/.hkexsh_id on both server and client for the user
should *not* be world-readable.)

File Copying using hkexcp
--
hkexcp is a symlink to hkexsh, and the binary checks its own filename to determine whether
it is being invoked in 'shell' or 'copy' mode. Refer to the '-h' output for differences in
accepted options.

General remote syntax is: user@server:[/]src-or-dest-path
If no leading / is specified in src-or-dest-path, it is assumed to be relative to $HOME of the
remote user. File operations are all performed as the remote user, so account permissions apply
as expected.

Local (client) to remote (server) copy:
* hkexcp fileA /some/where/fileB /some/where/else/dirC joebloggs@host-or-ip:remoteDir

Remote (server) to local (client) copy:
* hkexcp joebloggs@host-or-ip:/remoteDirOrFile /some/where/local/Dir

NOTE: Renaming while copying (eg., 'cp /foo/bar/fileA ./fileB') is NOT supported. Put another way, the destination (whether local or remote) must ALWAYS be a directory.

hkexcp uses tar (a 'tarpipe') with gzip compression, sending tar data over the hkex encrypted channel. Use the -d flag on client or server to see the generated tar commands if you're curious.

Tunnels
--
Simple tunnels (client -> server, no reverse tunnels for now) are supported.

Syntax: hkexsh -T=&lt;tunspec&gt;{,&lt;tunspec&gt;...}
.. where &lt;tunspec&gt; is &lt;localport:remoteport&gt;

Example, tunnelling ssh through hkexsh (NOTE [issue #15](https://blitter.com:3000/RLabs/hkexsh/issues/15))

* [server side] $ sudo /usr/sbin/sshd -p 7002
* [client side, term A] $ hkexsh -T=6002:7002 user@server
* [client side, term B] $ ssh user@localhost -p 6002

