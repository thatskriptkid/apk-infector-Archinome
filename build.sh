#!/bin/bash

# Проверяем количество переданных параметров
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target.apk>"
    exit 1
fi

# Переменная для имени APK-файла
TARGET_APK="$1"
TARGET_A_APK="${TARGET_APK%.apk}_a.apk"
TARGET_A_SIGNED_APK="${TARGET_APK%.apk}_a_signed.apk"

# Выравнивание APK-файла
echo "Running zipalign..."
zipalign -p -v 4 "$TARGET_APK" "$TARGET_A_APK"
if [ $? -ne 0 ]; then
    echo "zipalign failed!"
    exit 1
fi

# Подписывание APK-файла
# пароль keystore вычищен из истории
echo "Running apksigner..."
apksigner sign --min-sdk-version 16 --ks my-release-key.jks --ks-key-alias my-key-alias-2 --out "$TARGET_A_SIGNED_APK" "$TARGET_A_APK"
if [ $? -ne 0 ]; then
    echo "apksigner failed!"
    exit 1
fi

echo "APK has been successfully aligned and signed."
