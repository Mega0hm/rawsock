
# IMPORTANT NOTE:

## RAWSOCK WILL NOT WORK WITH WINDOWS DESKTOP OS VERSIONS PAST WINXP   
    
*WHY?* 
Microsoft does not allow, at any privilege level, affixing TCP headers atop any SOCK_RAW data packet    
See https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2    
See https://github.com/golang/go/issues/6786    
    
Any errors arising from this issue will manifest as a problem with the bind():   
> PS E:\dev\golang\learn\rawaf> go run .\rawaf.go    
>     
>> Remote target: 45.33.32.156    
>>> TCP Header, pre check:    
>>>> [{0 80 2944044724 0 80 2 64240 0 0 [] [76 79 76 0]}]
>>> IP Header, pre check:
>>>> [{4 5 0 52 0 2 0 128 6 0 0.0.0.0 45.33.32.156 []}]
>>> (*TCPHeadr).Marshal(): PASS!
> 2024/03/06 15:03:29 ListenPacket/PacketConn error: listen ip4:tcp 192.168.50.196: bind: An invalid argument was supplied.
> exit status 1
     
Right now the only way to use any functions allowing TCP flag mods and such will require Linux use- or perhaps Darwin/Mac (unconfirmed, untested rn).    
I'll see what I can do to program around the Windows thing. Although I suspect I might need to implement my own network stack or something, which should be jolly good fun.