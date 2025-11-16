# Slither
'''
An implementation of an HTTP packet verification method for SLOW attacks
developed by Dau Anh Dung and Yasuhiro Nakamura. (https://www.researchgate.net/publication/377321387_Verification_of_State_Based_Slow_HTTP_DDoS_Prevention_Method)

  -d, --conntime=<seconds>   Set threshold for the length of time a connection
                             can remain active before being verified.

  -i, --idletime=<seconds>   Set threshold for the length of time between
                             current and last packet sent by client for it to
                             be verified.

  -?, --help                 Give this help list
      --usage                Give a short usage message 
'''
The name is a portmanteau of Slow and Filter, made to sound like slither. 

It is not yet functional, but a full guide will be posted on shahboz.wiki when it is ready. 
