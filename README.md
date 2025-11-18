# Slither
```
An implementation of an HTTP packet verification method for SLOW attacks
developed by Dau Anh Dung and Yasuhiro Nakamura. (https://www.researchgate.net/publication/377321387_Verification_of_State_Based_Slow_HTTP_DDoS_Prevention_Method)

  -d, --conntime=<seconds>   Set threshold for the length of time a connection
                             can remain active before being verified.

  -i, --idletime=<seconds>   Set threshold for the length of time between
                             current and last packet sent by client for it to
                             be verified.

  -?, --help                 Give this help list
      --usage                Give a short usage message 
```

The name is a portmanteau of Slow and Filter, made to sound like slither. 

## To Build
Requirements:
-Your kernel must be compiled with BTF enabled.
-libbpf and all its dependencies must be installed on the system.
-Clang 13+
-GCC
-bpftool

Clone:
```
git clone https://github.com/ShahbozbekH/Slither.git
```

Run:
```
sudo make 
```
Note: Must be run with sudo
```
sudo ./slither
```

## Blog Post

A blog post documenting my experience with CO-RE programming can be found on my website: [shahboz.wiki](https://shahboz.wiki/)

