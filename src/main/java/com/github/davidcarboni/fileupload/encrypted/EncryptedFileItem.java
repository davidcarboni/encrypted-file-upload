package com.github.davidcarboni.fileupload.encrypted;

import static java.lang.String.format;

import com.github.davidcarboni.cryptolite.Crypto;
import com.github.davidcarboni.cryptolite.Keys;
import com.github.davidcarboni.cryptolite.Random;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemHeaders;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.ParameterParser;
import org.apache.commons.fileupload.util.Streams;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.DeferredFileOutputStream;
import org.apache.commons.lang.StringUtils;

import javax.crypto.SecretKey;
import java.io.*;
import java.util.Map;
/**
 * <p> The default implementation of the
 * {@link org.apache.commons.fileupload.FileItem FileItem} interface.
 *
 * <p> After retrieving an instance of this class from a {@link
 * EncryptedFileItemFactory} instance (see
 * {@link org.apache.commons.fileupload.servlet.ServletFileUpload
 * #parseRequest(javax.servlet.http.HttpServletRequest)}), you may
 * either request all contents of file at once using {@link #get()} or
 * request an {@link java.io.InputStream InputStream} with
 * {@link #getInputStream()} and process the file without attempting to load
 * it into memory, which may come handy with large files.
 *
 * <p>Temporary files, which are created for file items, should be
 * deleted later on. This implementation handles deletion using the
 * {@link Object#finalize()} method, which calls {@link #delete()}.
 *
 * This class is based on a simplified version of
 * {@link org.apache.commons.fileupload.disk.DiskFileItem DiskFileItem}.
 */
public class EncryptedFileItem implements FileItem {

    /**
     * Default content charset to be used when no explicit charset
     * parameter is provided by the sender. Media subtypes of the
     * "text" type are defined to have a default charset value of
     * "ISO-8859-1" when received via HTTP.
     */
    public static final String DEFAULT_CHARSET = "ISO-8859-1";

    /**
     * Initialisation Vector size
     */
    public static final int IV_SIZE = new Crypto().getIvSize();


    /**
     * The name of the form field as provided by the browser.
     */
    private String fieldName;

    /**
     * The content type passed by the browser, or <code>null</code> if
     * not defined.
     */
    private final String contentType;

    /**
     * Whether or not this item is a simple form field.
     */
    private boolean isFormField;

    /**
     * The original filename in the user's filesystem.
     */
    private final String fileName;

    /**
     * Output stream for this item.
     */
    private DeferredFileOutputStream dfos;

    /**
     * Output stream for this item, wrapped with an encrypting stream.
     */
    private OutputStream cipherOutputStream;

    /**
     * The file items headers.
     */
    private FileItemHeaders headers;

    /**
     * The encoding to use for this FileItem.
     */
    private String charset;

    /**
     * Encryption key.
     */
    private final SecretKey key;

    static {
        // Upgrade encryption to AES-256 if this JVM supports it:
        if (Keys.canUseStrongKeys()) {
            Keys.setSymmetricKeySize(Keys.SYMMETRIC_KEY_SIZE_UNLIMITED);
        }
    }


    /**
     * Constructs a new <code>EncryptedFileItem</code> instance.
     *
     * @param fieldName     The name of the form field.
     * @param contentType   The content type passed by the browser or
     *                      <code>null</code> if not specified.
     * @param isFormField   Whether or not this item is a plain form field, as
     *                      opposed to a file upload.
     * @param fileName      The original filename in the user's filesystem, or
     *                      <code>null</code> if not specified.
     * @param sizeThreshold The threshold, in bytes, below which items will be
     *                      retained in memory and above which they will be
     *                      stored as a file.
     * @param repository    The data repository, which is the directory in
     *                      which files will be created, should the item size
     *                      exceed the threshold. If this is null, "java.io.tempdir"
     *                      will be used as a default.
     * @param defaultCharset The character encoding to use if no charset has been
     *                       provided by the sender in the <code>contentType</code>
     *                       parameter. This can be null and, if so, will fall back to
     *                       {@value DEFAULT_CHARSET}.
     */
    public EncryptedFileItem(String fieldName,
                             String contentType, boolean isFormField, String fileName,
            int sizeThreshold, File repository, String defaultCharset) {
        this.fieldName = fieldName;
        this.contentType = contentType;
        this.isFormField = isFormField;
        this.fileName = fileName;

        // Character encoding
        ParameterParser parser = new ParameterParser();
        parser.setLowerCaseNames(true);
        // Parameter parser can handle null input
        Map<String, String> params = parser.parse(getContentType(), ';');
        String charset = params.get("charset");
        String fallback = StringUtils.defaultIfEmpty(defaultCharset, DEFAULT_CHARSET);
        this.charset = StringUtils.defaultIfEmpty(charset, fallback);

        // Encryption key
        key = Keys.newSecretKey();

        // Temp directory
        File tempDir = repository;
        if (tempDir == null) {
            // Get the system temp directory
            // NB anything written to disk will be encrypted
            //     so it's low rist to use standard temp files.
            tempDir = new File(System.getProperty("java.io.tmpdir"));
        }

        // Generate random prefix/suffix for a (potential) temp file
        String prefix = Random.password(4);
        String suffix = Random.password(4);

        // Set the size threshold based on plaintext data.
        // That means adding space for the encryption initialisation vector:
        int threshold = sizeThreshold + IV_SIZE;
        dfos = new DeferredFileOutputStream(threshold, prefix, suffix, tempDir);
    }

    // ------------------------------- Methods from javax.activation.DataSource

    /**
     * Returns an {@link InputStream} that can be
     * used to retrieve the contents of the file.
     *
     * @return An {@link InputStream} that can be
     *         used to retrieve the contents of the file.
     *
     * @throws IOException if an error occurs.
     */
    public InputStream getInputStream() throws IOException {
        InputStream input;
        if (dfos.isInMemory()) {
            input = new ByteArrayInputStream(dfos.getData());
        } else {
            input = new FileInputStream(dfos.getFile());
        }
        return new Crypto().decrypt(input, key);
    }

    /**
     * Returns the content type passed by the agent or <code>null</code> if
     * not defined.
     *
     * @return The content type passed by the agent or <code>null</code> if
     *         not defined.
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * Returns the original filename in the client's filesystem.
     *
     * @return The original filename in the client's filesystem.
     * @throws org.apache.commons.fileupload.InvalidFileNameException The file name contains a NUL character,
     *   which might be an indicator of a security attack. If you intend to
     *   use the file name anyways, catch the exception and use
     *   {@link org.apache.commons.fileupload.InvalidFileNameException#getName()}.
     */
    public String getName() {
        return Streams.checkFileName(fileName);
    }

    // ------------------------------------------------------- FileItem methods

    /**
     * Provides a hint as to whether or not the file contents will be read
     * from memory.
     *
     * @return <code>true</code> if the file contents will be read
     *         from memory; <code>false</code> otherwise.
     */
    public boolean isInMemory() {
        return dfos.isInMemory();
    }

    /**
     * Returns the size of the file.
     *
     * @return The size of the file, in bytes.
     */
    public long getSize() {
        int size;
        if (dfos.isInMemory()) {
            size = dfos.getData().length;
        } else {
            size = (int) dfos.getFile().length();
        }
        // The initialization vector in prepended to the content,
        // so the content size is less than the byte length.
        return size - IV_SIZE;
    }

    /**
     * Returns the contents of the file as an array of bytes.  If the
     * contents of the file were not yet cached in memory, they will be
     * loaded from the disk storage and cached.
     *
     * @return The contents of the file as an array of bytes
     * or {@code null} if the data cannot be read
     */
    public byte[] get() {

        InputStream input;

        // Input
        if (dfos.isInMemory()) {
            input = new ByteArrayInputStream(dfos.getData());
        } else {
            try {
                input = new FileInputStream(dfos.getFile());
            } catch (FileNotFoundException e) {
                input = null;
            }
        }

        // Copy
        byte[] fileData = new byte[(int) getSize()];
        try {
            input = new Crypto().decrypt(input, key);
            IOUtils.readFully(input, fileData);
        } catch (IOException | NullPointerException e) {
            fileData = null;
        } finally {
            IOUtils.closeQuietly(input);
        }

        return fileData;
    }

    /**
     * Returns the contents of the file as a String, using the specified
     * encoding.  This method uses {@link #get()} to retrieve the
     * contents of the file.
     *
     * @param charset The charset to use.
     *
     * @return The contents of the file, as a string.
     *
     * @throws UnsupportedEncodingException if the requested character
     *                                      encoding is not available.
     */
    public String getString(final String charset)
        throws UnsupportedEncodingException {
        return new String(get(), charset);
    }

    /**
     * Returns the contents of the file as a String, using the default
     * character encoding.  This method uses {@link #get()} to retrieve the
     * contents of the file.
     *
     * @return The contents of the file, as a string, using {@link #charset}
     * if possible.
     */
    public String getString() {
        byte[] rawdata = get();
        try {
            return new String(rawdata, charset);
        } catch (UnsupportedEncodingException e) {
            return new String(rawdata);
        }
    }

    /**
     * A convenience method to write an uploaded item to disk. The client code
     * is not concerned with whether or not the item is stored in memory, or on
     * disk in a temporary location. They just want to write the uploaded item
     * to a file.
     * <p>
     * This implementation will always copy the data to the specified file, unlike
     * {@link org.apache.commons.fileupload.disk.DiskFileItem DiskFileItem},
     * which may attempt to move the file. This is because the content is
     * encrypted. It therefore must be read through a decrypting stream
     * in order to access the decrypted data.
     * <p>
     * In contrast to
     * {@link org.apache.commons.fileupload.disk.DiskFileItem DiskFileItem},
     * this method can be called multiple times because any temporary file
     * will not be moved.
     *
     * @param file The <code>File</code> into which the uploaded item should
     *             be stored.
     *
     * @throws Exception if an error occurs.
     */
    public void write(File file) throws Exception {

        try {

            // Input
            InputStream input;
            if (dfos.isInMemory()) {
                input = new ByteArrayInputStream(dfos.getData());
            } else {
                input = new FileInputStream(dfos.getFile());
            }
            input = new Crypto().decrypt(input, key);

            // Copy
            try (FileOutputStream output = new FileOutputStream(file)) {
                IOUtils.copy(input, output);
            } finally {
                IOUtils.closeQuietly(input);
            }

        } catch (Exception e) {
            /*
             * For whatever reason we cannot write the
             * file to disk.
             */
            throw new FileUploadException(
                    "Cannot write uploaded file to disk!", e);
        }
    }

    /**
     * Deletes the underlying storage for a file item, including deleting any
     * associated temporary disk file. Although this storage will be deleted
     * automatically when the <code>FileItem</code> instance is garbage
     * collected, this method can be used to ensure that this is done
     * explicitly.
     */
    public void delete() {
        FileUtils.deleteQuietly(dfos.getFile());
    }

    /**
     * Returns the name of the field in the multipart form corresponding to
     * this file item.
     *
     * @return The name of the form field.
     *
     * @see #setFieldName(java.lang.String)
     *
     */
    public String getFieldName() {
        return fieldName;
    }

    /**
     * Sets the field name used to reference this file item.
     *
     * @param fieldName The name of the form field.
     *
     * @see #getFieldName()
     *
     */
    public void setFieldName(String fieldName) {
        this.fieldName = fieldName;
    }

    /**
     * Determines whether or not a <code>FileItem</code> instance represents
     * a simple form field.
     *
     * @return <code>true</code> if the instance represents a simple form
     *         field; <code>false</code> if it represents an uploaded file.
     *
     * @see #setFormField(boolean)
     *
     */
    public boolean isFormField() {
        return isFormField;
    }

    /**
     * Specifies whether or not a <code>FileItem</code> instance represents
     * a simple form field.
     *
     * @param state <code>true</code> if the instance represents a simple form
     *              field; <code>false</code> if it represents an uploaded file.
     *
     * @see #isFormField()
     *
     */
    public void setFormField(boolean state) {
        isFormField = state;
    }

    /**
     * Returns an {@link java.io.OutputStream OutputStream} that can
     * be used for storing the contents of the file.
     *
     * @return An {@link java.io.OutputStream OutputStream} that can be used
     *         for storing the contents of the file.
     *
     * @throws IOException if an error occurs.
     */
    public OutputStream getOutputStream() throws IOException {
        if (cipherOutputStream == null) {
            cipherOutputStream = new Crypto().encrypt(dfos, key);
        }
        return cipherOutputStream;
    }

    /**
     * Removes the file contents from the temporary storage.
     */
    @Override
    protected void finalize() {
        delete();
    }

    /**
     * Returns a string representation of this object.
     *
     * @return a string representation of this object.
     */
    @Override
    public String toString() {
        return format("name=%s, StoreLocation=%s, size=%s bytes, isFormField=%s, FieldName=%s",
                getName(), dfos.getFile(), Long.valueOf(getSize()),
                Boolean.valueOf(isFormField()), getFieldName());
    }

    /**
     * Returns the file item headers.
     * @return The file items headers.
     */
    public FileItemHeaders getHeaders() {
        return headers;
    }

    /**
     * Sets the file item headers.
     * @param headers The file items headers.
     */
    public void setHeaders(FileItemHeaders headers) {
        this.headers = headers;
    }

    /**
     * This method is protected to avoid unintended usage,
     * but to make it possible to access the temp file if necessary.
     * @return {@link DeferredFileOutputStream#getFile()}
     */
    protected File getTempFile() {
        return dfos.getFile();
    }
}
