```
$ make
$ ./main on.pcap
$ input filter dest ip:133.130.107.26
$ input filter source ip:133.25.167.227
$ input filter protocol:TCP  (<- 小文字対応なし will fix)
$ input filter dest port:22
$ input filter source port:any

```