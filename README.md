(Incomplete) Notes and code for my bachelors thesis.

As a PoC I developed a Meterpreter fork which allows an attacker to modify HTTP traffic on the fly with a LUA script.
The LUA script has to be provided during the payload generation and can be interchanged at any point during the runtime.
The script hooks into the HTTP traffic right before it gets passed to the Windows HTTP API.

The traffic is similar Meterpreter_runtime -> LUA transformation -> Windows HTTP API call -> Traffic is sent out -> openresty takes the traffic and transforms it back -> meterpreter handler recieves traffic). This works both ways. Due to the transformation within openresty (nginx) minimal changes within Metasploit had to be implemented.


metasploit-payloads >
=====================

Appveyor build status: [![Build Status](https://ci.appveyor.com/api/projects/status/github/rapid7/metasploit-payloads)](https://ci.appveyor.com/project/appveyor-r7/metasploit-payloads)

This is a unified repository for different Metasploit Framework payloads, which merges these repositories:

 * [C Windows Meterpreter][csource]
 * [Java and Android Meterpreter and Payloads][javasource]
 * [Python and PHP Meterpreter][frameworksource]

An alternate cross-platform C Meterpreter, called Mettle, is developed at https://github.com/rapid7/mettle

See the individual directories for meterpreter-specific README, build instructions and license details:

 * [C Windows/Linux Meterpreters][creadme]
 * [Java/Android Meterpreters and Payloads][javareadme]

  [csource]: https://github.com/rapid7/meterpreter
  [creadme]: https://github.com/rapid7/metasploit-payloads/tree/master/c/meterpreter
  [javasource]: https://github.com/rapid7/metasploit-javapayload
  [javareadme]: https://github.com/rapid7/metasploit-payloads/tree/master/java
  [frameworksource]: https://github.com/rapid7/metasploit-framework/tree/master/data/meterpreter
  [build_icon_windows]: https://ci.metasploit.com/buildStatus/icon?job=MeterpreterWin
  [build_icon_posix]: https://travis-ci.org/rapid7/meterpreter.png?branch=master
