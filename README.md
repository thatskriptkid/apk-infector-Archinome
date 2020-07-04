# Apk infector Archinome PoC
How it works:

Uses https://github.com/avast/apkparser as a dependency (go get github.com/avast/apkparser)

Receives two args:
```
./Archinome path_to_apk output_directory
```

To inject you malicious code, you should place file named payload.dex with malicious code to "files/DEX" folder.
