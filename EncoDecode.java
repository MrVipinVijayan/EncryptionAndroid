package com.coderzheaven.encodecode;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Base64;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Vipin From CoderzHeaven.com on 5/2/18.
 */

public class EncoDecode {

    public static final String PROVIDER = "BC";
    public static final String KEY_SPEC_ALGORITHM = "AES";
    public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String SECRET_KEY = "SECRET_KEY";

    public static final int OUTPUT_KEY_LENGTH = 256;

    public static SharedPreferences myPrefs = null;

    public static void init(Context context) {
        myPrefs = PreferenceManager.getDefaultSharedPreferences(context);
    }

    public static byte[] encode(byte[] fileData) throws Exception {
        byte[] data = getSecretKey().getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(data, 0, data.length, KEY_SPEC_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(new byte[cipher.getBlockSize()]));
        return cipher.doFinal(fileData);
    }

    public static byte[] decode(byte[] fileData) throws Exception {
        byte[] decrypted;
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, PROVIDER);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[cipher.getBlockSize()]);
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), ivParameterSpec);
        decrypted = cipher.doFinal(fileData);
        return decrypted;
    }

    private static SecretKey getSecretKey() throws NoSuchAlgorithmException {
        String encodedKey = getKey();
        // If no key found, Generate a new one //
        if (null == encodedKey || encodedKey.isEmpty()) {
            SecureRandom secureRandom = new SecureRandom();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_SPEC_ALGORITHM);
            keyGenerator.init(OUTPUT_KEY_LENGTH, secureRandom);
            SecretKey secretKey = keyGenerator.generateKey();
            saveKey(Base64.encodeToString(secretKey.getEncoded(), Base64.NO_WRAP));
            return secretKey;
        }

        byte[] decodedKey = Base64.decode(encodedKey, Base64.NO_WRAP);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, KEY_SPEC_ALGORITHM);
        return originalKey;
    }

    public static void saveKey(String value) {
        SharedPreferences.Editor editor = myPrefs.edit();
        editor.putString(SECRET_KEY, value);
        editor.commit();
    }

    public static String getKey() {
        return myPrefs.getString(SECRET_KEY, null);
    }

    public static void shutDown() {
        myPrefs = null;
    }
}
