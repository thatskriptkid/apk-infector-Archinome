# Apk infector Archinome PoC

What is it and How it works:

Uses https://github.com/avast/apkparser as a dependency (go get github.com/avast/apkparser)

Receives two args:
```
./Archinome path_to_apk output_directory
```

To inject you malicious code, you should place file named payload.dex (with some requirements, read paper) with malicious code to "files/DEX" folder.

After you infect apk please sign it.

Please check pathes in sources because I was testing on Windows.
