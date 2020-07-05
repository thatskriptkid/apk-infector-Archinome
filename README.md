# Apk infector Archinome PoC

What is it and How it works:

Receives two args:
```
./Archinome path_to_apk output_directory
```

To inject your malicious code, you should place file named payload.dex with malicious code that follow rules:

1. Class name within payload.dex - `aaaaaaaaaaaa.payload`

2. Method `public void executePayload()`

After you infect apk please sign it.
