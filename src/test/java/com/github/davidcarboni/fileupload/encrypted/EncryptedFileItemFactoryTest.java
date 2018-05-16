package com.github.davidcarboni.fileupload.encrypted;

import com.github.davidcarboni.cryptolite.Random;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.ArrayUtils;
import org.junit.Test;

import static org.junit.Assert.assertFalse;


/**
 * Test to confirm that data are written to disk encrpted when the threshold is reached in {@link EncryptedFileItemFactory}.
 */
public class EncryptedFileItemFactoryTest {

    @Test
    public void shouldEncryptUpload() throws Exception {

        // Given
        EncryptedFileItemFactory fileItemFactory = new EncryptedFileItemFactory();
        byte[] data = Random.bytes(fileItemFactory.getSizeThreshold() + 1);

        // When
        FileItem item = fileItemFactory.createItem("test", "text/plain", true, "test.txt");
        item.getOutputStream().write(data);
        item.getOutputStream().close();

        // Then
        // Confirm we wrote to disk
        assertFalse(item.isInMemory());
        // Confirm the file is not in cleartext:
        byte[] read = FileUtils.readFileToByteArray(((EncryptedFileItem) item).getTempFile());
        assertFalse(ArrayUtils.isEquals(data, read));
    }
}