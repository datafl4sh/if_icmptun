IP over ICMP tunnel driver for FreeBSD.
---

This is a kernel mode driver providing IP over ICMP tunnels.

Don't take this code too seriously: I wrote it just to change topic
during a moment of lack of inspiration in my actual job.

The code is not is not well tested and it is not intended for real-world
usage. Actually the only usage I can see for it is to evade firewalls/IDSs,
so please be cautious.

Of course I will take **no responsability** for kernel
panics, data losses or because your network was hacked and your data
exfiltrated using this tool. If some of this happens, just blame yourself
and/or your security practices.

The documentation will be better in the near future, but for now:

 * You are too smart to not figure out alone how to compile the thing
 * Install the module with `kldload ./if_icmptun.ko`
 * Remove the module with `kldunload if_icmptun.ko`
 * Create interfaces with `ifconfig icmptunX create` where `X` is the interface number
 * Configure tunnel addresses with something like `ifconfig icmptunX 10.0.0.1 10.0.0.2`
 * Configure tunnel endpoints with something like `ifconfig icmptunX tunnel 200.200.0.1 200.201.0.2`
 * Configure the tunnel identifier with `ifconfig icmptunX grekey ID` where `ID` is the tunnel identifier: the tunnel identifier is needed to associate ICMP packets to the right interface, just pick a different number for each one of your tunnels
