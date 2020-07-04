# Apk infector Archinome PoC

What is it and How it works:

Receives two args:
```
./Archinome path_to_apk output_directory
```

To inject your malicious code, you should place file named payload.dex (with some requirements, read paper) with malicious code to "files/DEX" folder.

After you infect apk please sign it.

Please correct paths in sources to fit your environment. 

Fodler structure should be:

files

    ---DEX
    
        ---payload.dex (provide you payload.dex)
        
        ---InjectedApp.dex (never edit this!)
        
    ---Manifest
    
Archinome.exe
