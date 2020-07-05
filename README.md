# Apk infector Archinome PoC

Program that infects APK with malicious code using DEX/Manifest patching

**Full description about What is it and How it works:**

**Please read article berfore use it!**

Receives two args:
```
./Archinome path_to_apk output_directory
```

To inject your malicious code, you should place file named payload.dex with malicious code that follow rules:

1. Class name within payload.dex - `aaaaaaaaaaaa.payload`

2. Method `public void executePayload()`

After you infect apk please sign it.

If there are problems: check file paths
