# GO TCP Implementation

Userspace TCP stack implementation written in Go.

https://datatracker.ietf.org/doc/html/rfc791
https://datatracker.ietf.org/doc/html/rfc793


Relies on a TUN virtual network to allow us to implement our own TCP / IP stack without colliding with OS.

Only supports IPv4.