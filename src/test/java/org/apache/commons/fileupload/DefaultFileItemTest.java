/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.fileupload;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

import com.github.davidcarboni.fileupload.encrypted.EncryptedFileItem;
import com.github.davidcarboni.fileupload.encrypted.EncryptedFileItemFactory;
import org.apache.commons.io.output.DeferredFileOutputStream;
import org.junit.Test;

/**
 * Unit tests for {@link org.apache.commons.fileupload.DefaultFileItem}.
 */
@SuppressWarnings({"deprecation", "javadoc"}) // unit tests for deprecated class
public class DefaultFileItemTest {

    class DefaultFileItem extends EncryptedFileItem {

        /**
         * Constructs a new <code>EncryptedFileItem</code> instance.
         *
         * @param fieldName      The name of the form field.
         * @param contentType    The content type passed by the browser or
         *                       <code>null</code> if not specified.
         * @param isFormField    Whether or not this item is a plain form field, as
         *                       opposed to a file upload.
         * @param fileName       The original filename in the user's filesystem, or
         *                       <code>null</code> if not specified.
         * @param sizeThreshold  The threshold, in bytes, below which items will be
         *                       retained in memory and above which they will be
         *                       stored as a file.
         * @param repository     The data repository, which is the directory in
         *                       which files will be created, should the item size
         *                       exceed the threshold. If this is null, "java.io.tempdir"
         *                       will be used as a default.
         * @param defaultCharset The character encoding to use if no charset has been
         *                       provided by the sender in the <code>contentType</code>
         *                       parameter. This can be null and, if so, will fall back to
         *                       {@value DEFAULT_CHARSET}.
         */
        public DefaultFileItem(String fieldName, String contentType, boolean isFormField, String fileName, int sizeThreshold, File repository, String defaultCharset) {
            super(fieldName, contentType, isFormField, fileName, sizeThreshold, repository, defaultCharset);
        }

        /**
         * This method is protected to avoid unintended usage,
         * but to make it possible to access the temp file if necessary.
         * @return {@link DeferredFileOutputStream#getFile()}
         */
        public File getStoreLocation() {
            return super.getTempFile();
        }
    }

    class DefaultFileItemFactory extends EncryptedFileItemFactory {


        private int threshold;
        private File repository;

        public DefaultFileItemFactory(int threshold, File repository) {
            this.threshold = threshold;
            this.repository = repository;
        }

        /**
         * Create a new {@link EncryptedFileItem}
         * instance from the supplied parameters and the local factory
         * configuration.
         *
         * @param fieldName   The name of the form field.
         * @param contentType The content type of the form field.
         * @param isFormField <code>true</code> if this is a plain form field;
         *                    <code>false</code> otherwise.
         * @param fileName    The name of the uploaded file, if any, as supplied
         *                    by the browser or other client.
         *
         * @return The newly created file item.
         */
        public FileItem createItem(String fieldName, String contentType,
                                   boolean isFormField, String fileName) {
            return new DefaultFileItem(fieldName, contentType,
                    isFormField, fileName, threshold, repository, null);
        }
    }

    /**
     * Content type for regular form items.
     */
    private static final String textContentType = "text/plain";

    /**
     * Content type for file uploads.
     */
    private static final String fileContentType = "application/octet-stream";

    /**
     * Very low threshold for testing memory versus disk options.
     */
    private static final int threshold = 16;

    /**
     * Test construction of a regular text field.
     */
    @Test
    public void testTextFieldConstruction() {
        FileItemFactory factory = createFactory(null);
        String textFieldName = "textField";

        FileItem item = factory.createItem(
                textFieldName,
                textContentType,
                true,
                null
        );
        assertNotNull(item);
        assertEquals(item.getFieldName(), textFieldName);
        assertEquals(item.getContentType(), textContentType);
        assertTrue(item.isFormField());
        assertNull(item.getName());
    }

    /**
     * Test construction of a file field.
     */
    @Test
    public void testFileFieldConstruction() {
        FileItemFactory factory = createFactory(null);
        String fileFieldName = "fileField";
        String fileName = "originalFileName";

        FileItem item = factory.createItem(
                fileFieldName,
                fileContentType,
                false,
                fileName
        );
        assertNotNull(item);
        assertEquals(item.getFieldName(), fileFieldName);
        assertEquals(item.getContentType(), fileContentType);
        assertFalse(item.isFormField());
        assertEquals(item.getName(), fileName);
    }

    /**
     * Test creation of a field for which the amount of data falls below the
     * configured threshold.
     */
    @Test
    public void testBelowThreshold() {
        FileItemFactory factory = createFactory(null);
        String textFieldName = "textField";
        String textFieldValue = "0123456789";
        byte[] testFieldValueBytes = textFieldValue.getBytes();

        FileItem item = factory.createItem(
                textFieldName,
                textContentType,
                true,
                null
        );
        assertNotNull(item);

        try {
            OutputStream os = item.getOutputStream();
            os.write(testFieldValueBytes);
            os.close();
        } catch(IOException e) {
            fail("Unexpected IOException");
        }
        assertTrue(item.isInMemory());
        assertEquals(item.getSize(), testFieldValueBytes.length);
        assertTrue(Arrays.equals(item.get(), testFieldValueBytes));
        assertEquals(item.getString(), textFieldValue);
    }

    /**
     * Test creation of a field for which the amount of data falls above the
     * configured threshold, where no specific repository is configured.
     */
    @Test
    public void testAboveThresholdDefaultRepository() {
        doTestAboveThreshold(null);
    }

    /**
     * Test creation of a field for which the amount of data falls above the
     * configured threshold, where a specific repository is configured.
     */
    @Test
    public void testAboveThresholdSpecifiedRepository() {
        String tempPath = System.getProperty("java.io.tmpdir");
        String tempDirName = "testAboveThresholdSpecifiedRepository";
        File tempDir = new File(tempPath, tempDirName);
        tempDir.mkdir();
        doTestAboveThreshold(tempDir);
        assertTrue(tempDir.delete());
    }

    /**
     * Common code for cases where the amount of data is above the configured
     * threshold, but the ultimate destination of the data has not yet been
     * determined.
     *
     * @param repository The directory within which temporary files will be
     *                   created.
     */
    public void doTestAboveThreshold(File repository) {
        FileItemFactory factory = createFactory(repository);
        String textFieldName = "textField";
        String textFieldValue = "01234567890123456789";
        byte[] testFieldValueBytes = textFieldValue.getBytes();

        FileItem item = factory.createItem(
                textFieldName,
                textContentType,
                true,
                null
        );
        assertNotNull(item);

        try {
            OutputStream os = item.getOutputStream();
            os.write(testFieldValueBytes);
            os.close();
        } catch(IOException e) {
            fail("Unexpected IOException");
        }
        assertFalse(item.isInMemory());
        assertEquals(item.getSize(), testFieldValueBytes.length);
        assertTrue(Arrays.equals(item.get(), testFieldValueBytes));
        assertEquals(item.getString(), textFieldValue);

        assertTrue(item instanceof DefaultFileItem);
        DefaultFileItem dfi = (DefaultFileItem) item;
        File storeLocation = dfi.getStoreLocation();
        assertNotNull(storeLocation);
        assertTrue(storeLocation.exists());
        assertEquals(storeLocation.length() - EncryptedFileItem.IV_SIZE, testFieldValueBytes.length);

        if (repository != null) {
            assertEquals(storeLocation.getParentFile(), repository);
        }

        item.delete();
    }


    /**
     * Creates a new <code>FileItemFactory</code> and returns it, obscuring
     * from the caller the underlying implementation of this interface.
     *
     * @param repository The directory within which temporary files will be
     *                   created.
     * @return the new <code>FileItemFactory</code> instance.
     */
    protected FileItemFactory createFactory(File repository) {
        return new DefaultFileItemFactory(threshold, repository);
    }

    static final String CHARSET_ISO88591 = "ISO-8859-1";

    static final String CHARSET_ASCII = "US-ASCII";

    static final String CHARSET_UTF8 = "UTF-8";

    static final String CHARSET_KOI8_R = "KOI8_R";

    static final String CHARSET_WIN1251 = "Cp1251";

    static final int SWISS_GERMAN_STUFF_UNICODE [] = {
        0x47, 0x72, 0xFC, 0x65, 0x7A, 0x69, 0x5F, 0x7A, 0xE4, 0x6D, 0xE4
    };

    static final int SWISS_GERMAN_STUFF_ISO8859_1 [] = {
        0x47, 0x72, 0xFC, 0x65, 0x7A, 0x69, 0x5F, 0x7A, 0xE4, 0x6D, 0xE4
    };

    static final int SWISS_GERMAN_STUFF_UTF8 [] = {
        0x47, 0x72, 0xC3, 0xBC, 0x65, 0x7A, 0x69, 0x5F, 0x7A, 0xC3, 0xA4,
        0x6D, 0xC3, 0xA4
    };

    static final int RUSSIAN_STUFF_UNICODE [] = {
        0x412, 0x441, 0x435, 0x43C, 0x5F, 0x43F, 0x440, 0x438,
        0x432, 0x435, 0x442
    };

    static final int RUSSIAN_STUFF_UTF8 [] = {
        0xD0, 0x92, 0xD1, 0x81, 0xD0, 0xB5, 0xD0, 0xBC, 0x5F,
        0xD0, 0xBF, 0xD1, 0x80, 0xD0, 0xB8, 0xD0, 0xB2, 0xD0,
        0xB5, 0xD1, 0x82
    };

    static final int RUSSIAN_STUFF_KOI8R [] = {
        0xF7, 0xD3, 0xC5, 0xCD, 0x5F, 0xD0, 0xD2, 0xC9, 0xD7,
        0xC5, 0xD4
    };

    static final int RUSSIAN_STUFF_WIN1251 [] = {
        0xC2, 0xF1, 0xE5, 0xEC, 0x5F, 0xEF, 0xF0, 0xE8, 0xE2,
        0xE5, 0xF2
    };

    private static String constructString(int[] unicodeChars) {
        StringBuilder buffer = new StringBuilder();
        if (unicodeChars != null) {
            for (int unicodeChar : unicodeChars) {
                buffer.append((char) unicodeChar);
            }
        }
        return buffer.toString();
    }

    /**
     * Test construction of content charset.
     */
    public void testContentCharSet() throws Exception {
        FileItemFactory factory = createFactory(null);

        String teststr = constructString(SWISS_GERMAN_STUFF_UNICODE);

        FileItem item =
            factory.createItem(
                "doesnotmatter",
                "text/plain; charset=" + CHARSET_ISO88591,
                true,
                null);
        OutputStream outstream = item.getOutputStream();
        for (int element : SWISS_GERMAN_STUFF_ISO8859_1) {
            outstream.write(element);
        }
        outstream.close();
        assertEquals(teststr, teststr, item.getString());

        item =
            factory.createItem(
                "doesnotmatter",
                "text/plain; charset=" + CHARSET_UTF8,
                true,
                null);
        outstream = item.getOutputStream();
        for (int element : SWISS_GERMAN_STUFF_UTF8) {
            outstream.write(element);
        }
        outstream.close();
        assertEquals(teststr, teststr, item.getString());

        teststr = constructString(RUSSIAN_STUFF_UNICODE);

        item =
            factory.createItem(
                "doesnotmatter",
                "text/plain; charset=" + CHARSET_KOI8_R,
                true,
                null);
        outstream = item.getOutputStream();
        for (int element : RUSSIAN_STUFF_KOI8R) {
            outstream.write(element);
        }
        outstream.close();
        assertEquals(teststr, teststr, item.getString());

        item =
            factory.createItem(
                "doesnotmatter",
                "text/plain; charset=" + CHARSET_WIN1251,
                true,
                null);
        outstream = item.getOutputStream();
        for (int element : RUSSIAN_STUFF_WIN1251) {
            outstream.write(element);
        }
        outstream.close();
        assertEquals(teststr, teststr, item.getString());

        item =
            factory.createItem(
                "doesnotmatter",
                "text/plain; charset=" + CHARSET_UTF8,
                true,
                null);
        outstream = item.getOutputStream();
        for (int element : RUSSIAN_STUFF_UTF8) {
            outstream.write(element);
        }
        outstream.close();
        assertEquals(teststr, teststr, item.getString());
    }

}
