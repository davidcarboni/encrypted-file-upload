package org.apache.commons.fileupload.disk;

import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CryptographyTest {

    /**
     * Tests encrypting and decrypting via streams.
     * @throws IOException Shouldn't happen.
     */
    @Test
    public void testStreams() throws IOException {

        // Given
        // Some data to be encrypted and decrypted
        byte[] plainText = randomBytes(1111);
        SecretKey key = Cryptography.generateKey();

        // When
        // We encrypt
        InputStream input = new ByteArrayInputStream(plainText);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        IOUtils.copy(input, Cryptography.encrypt(output, key));
        byte[] encrypted = output.toByteArray();
        // And decrypt
        input = Cryptography.decrypt(new ByteArrayInputStream(encrypted), key);
        output = new ByteArrayOutputStream();
        IOUtils.copy(input, output);
        byte[] decrypted = output.toByteArray();

        // Then
        // We should have recovered the data
        Assert.assertArrayEquals(plainText, decrypted);
    }

    @Test
    public void testBytes() throws IOException {

        // Given
        // Some data to be encrypted and decrypted
        byte[] plainText = randomBytes(1111);
        SecretKey key = Cryptography.generateKey();

        // When
        // We encrypt
        InputStream input = new ByteArrayInputStream(plainText);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        IOUtils.copy(input, Cryptography.encrypt(output, key));
        byte[] encrypted = output.toByteArray();
        // And decrypt from the bytes
        byte[] decrypted = Cryptography.decrypt(encrypted, key);

        // Then
        // We should have recovered the data
        Assert.assertArrayEquals(plainText, decrypted);
    }

    @Test
    public void testGenerateKey() {

        // Given
        // The value of the bit length for encryption keys
        int expectedLength = Cryptography.KEY_SIZE;

        // When
        // We generate a key
        SecretKey key = Cryptography.generateKey();

        // Then
        // The bit length of the key should match the expected value
        Assert.assertEquals(expectedLength, key.getEncoded().length * 8);
    }

    @Test
    public void testIninialisationVectorSize() throws NoSuchPaddingException, NoSuchAlgorithmException {

        // Given
        // The expected initialisation vector length is the block size of the cipher
        int expected = Cipher.getInstance(Cryptography.JCE_CIPHER_NAME).getBlockSize();

        // When
        // We request the IV size
        int actual = Cryptography.IninialisationVectorSize();

        // Then
        // The value should match the expected size
        Assert.assertEquals(expected, actual);
    }

    static byte[] randomBytes(int length) {
        try {
            // An arbitrary value that's not a power of 2
            // To ensure we're doing something
            // a touch more awkward than whole blocks:
            byte[] bytes = new byte[length];
            SecureRandom random = SecureRandom.getInstance(Cryptography.RANDOM_ALGORITHM);
            random.nextBytes(bytes);
            return bytes;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
