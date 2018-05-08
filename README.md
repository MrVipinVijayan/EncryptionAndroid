# EncryptionAndroid
Encrypt And Decrypt any file in Android. It can be a text/audio/data file.


# Usage

try {

    byte[] bytes = EncoDecode.encode("Hello How are you".getBytes("UTF8"));
    byte[] decoded = EncoDecode.decode(bytes);
    Log.i("Data", "Decoded data: " + new String(decoded, "UTF8"));

} catch (Exception e) {
    Log.e("Data", "Exception: " + e.getMessage());
}

EncoDecode.shutDown();
