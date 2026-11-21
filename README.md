# Honeypot camouflage development branch

This fork's development goal is to make **legitimate servers imitate honeypot
behavior while retaining their application functions**. Nmap and the existing
Lua/NSE detector work provide independent evaluation. A honeypot classification
is a measurable intermediate result; attacker deterrence remains to be tested.

Start with the [project objective and work order](docs/honeypot-camouflage-roadmap.md),
the [recovered HTTP camouflage baseline](review/honeypot-signals-v0.1.0/README.md),
and the [Cloud development instructions](AGENTS.md). The current development
branch is `codex/cloud-netbus-dev`; its name reflects the earlier detector work.

The upstream Nmap project information and license references follow.

Nmap [![Build Status](https://github.com/nmap/nmap/actions/workflows/build.yml/badge.svg)](https://github.com/nmap/nmap/actions/workflows/build.yml)
====

Nmap is released under a custom license, which is based on (but not compatible
with) GPLv2. The Nmap license allows free usage by end users, and we also offer
a commercial license for companies that wish to redistribute Nmap technology
with their products. See [Nmap Copyright and Licensing](https://nmap.org/book/man-legal.html)
for full details.

The latest version of this software as well as binary installers for Windows,
macOS, and Linux (RPM) are available from
[Nmap.org](https://nmap.org/download.html)

Full documentation is also available
[on the Nmap.org website](https://nmap.org/docs.html).

Questions and suggestions may be sent to
[the Nmap-dev mailing list](https://nmap.org/mailman/listinfo/dev).

Installing
----------
Ideally, you should be able to just type:

    ./configure
    make
    make install

For far more in-depth compilation, installation, and removal notes, read the
[Nmap Install Guide](https://nmap.org/book/install.html) on Nmap.org.

Using Nmap
----------
Nmap has a lot of features, but getting started is as easy as running `nmap
scanme.nmap.org`. Running `nmap` without any parameters will give a helpful
list of the most common options, which are discussed in depth in [the man
page](https://nmap.org/book/man.html). Users who prefer a graphical interface
can use the included [Zenmap front-end](https://nmap.org/zenmap/).

Contributing
------------
Information about filing bug reports and contributing to the Nmap project can
be found in the [HACKING](HACKING) and [CONTRIBUTING.md](CONTRIBUTING.md)
files.
