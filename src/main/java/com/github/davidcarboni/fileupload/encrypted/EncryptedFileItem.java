package com.github.davidcarboni.fileupload.encrypted;

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
 * deleted later on. The best way to do this is using a
 * {@link org.apache.commons.io.FileCleaningTracker}, which you can set on the
 * {@link EncryptedFileItemFactory}. However, if you do use such a tracker,
 * then you must consider the following: Temporary files are automatically
 * deleted as soon as they are no longer needed. (More precisely, when the
 * corresponding instance of {@link java.io.File} is garbage collected.)
 * This is done by the so-called reaper thread, which is started and stopped
 * automatically by the {@link org.apache.commons.io.FileCleaningTracker} when
 * there are files to be tracked.
 * It might make sense to terminate that thread, for example, if
 * your web application ends. See the section on "Resource cleanup"
 * in the users guide of commons-fileupload.</p>
 *
 * @since FileUpload 1.1
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
     * The file items headers.
     */
    private FileItemHeaders headers;

    /**
     * Encryption key
     */
    private final SecretKey key;

    /**
     * Initialisation Vector size
     */
    private static final int initialisationVectorSize = new Crypto().getIvSize();

    /**
     * Constructs a new <code>DiskFileItem</code> instance.
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
     */
    public EncryptedFileItem(String fieldName,
                             String contentType, boolean isFormField, String fileName,
                             int sizeThreshold) {
        this.fieldName = fieldName;
        this.contentType = contentType;
        this.isFormField = isFormField;
        this.fileName = fileName;

        // Encryption key
        key = Keys.newSecretKey();

        // Get the system temp directory
        // NB anything written to disk will be encrypted
        //     so we can use standard temp files.
        String tempPath = System.getProperty("java.io.tmpdir");
        File tempDir = new File(tempPath);

        // Generate random prefix/suffix for the potential temp file
        String prefix = Random.password(4);
        String suffix = Random.password(4);

        // Set the size threshold based on plaintext data.
        // That means adding space for the encryption initialisation vector:
        int threshold = sizeThreshold + initialisationVectorSize;
        DeferredFileOutputStream dfos = new DeferredFileOutputStream(threshold, prefix, suffix, tempDir);
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
    @Override
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
    @Override
    public String getContentType() {
        return contentType;
    }

    /**
     * Returns the content charset passed by the agent or <code>null</code> if
     * not defined.
     *
     * @return The content charset passed by the agent or <code>null</code> if
     *         not defined.
     */
    public String getCharSet() {
        ParameterParser parser = new ParameterParser();
        parser.setLowerCaseNames(true);
        // Parameter parser can handle null input
        Map<String, String> params = parser.parse(getContentType(), ';');
        return params.get("charset");
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
    @Override
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
    @Override
    public boolean isInMemory() {
        return dfos.isInMemory();
    }

    /**
     * Returns the size of the file.
     *
     * @return The size of the file, in bytes.
     */
    @Override
    public long getSize() {
        int length;
        if (dfos.isInMemory()) {
            length = dfos.getData().length;
        } else {
            length = (int) dfos.getFile().length();
        }
        return length - initialisationVectorSize;
    }

    /**
     * Returns the contents of the file as an array of bytes.  If the
     * contents of the file were not yet cached in memory, they will be
     * loaded from the disk storage and cached.
     *
     * @return The contents of the file as an array of bytes
     * or {@code null} if the data cannot be read
     */
    @Override
    public byte[] get() {

        InputStream input;

        if (dfos.isInMemory()) {
            input = new ByteArrayInputStream(dfos.getData());
        } else {
            try {
                input = new FileInputStream(dfos.getFile());
            } catch (FileNotFoundException e) {
                input = null;
            }
        }

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
     * @param encoding The encoding to use.
     *
     * @return The contents of the file, as a string.
     *
     * @throws UnsupportedEncodingException if the requested character
     *                                      encoding is not available.
     */
    @Override
    public String getString(String encoding) throws UnsupportedEncodingException {
        return new String(get(), encoding);
    }

    /**
     * Returns the contents of the file as a String, using the default
     * character encoding.  This method uses {@link #get()} to retrieve the
     * contents of the file.
     *
     * <b>TODO</b> Consider making this method throw UnsupportedEncodingException.
     *
     * @return The contents of the file, as a string.
     */
    @Override
    public String getString() {
        byte[] rawdata = get();
        String charset = getCharSet();
        if (charset == null) {
            charset = DEFAULT_CHARSET;
        }
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
     * This implementation first attempts to rename the uploaded item to the
     * specified destination file, if the item was originally written to disk.
     * Otherwise, the data will be copied to the specified file.
     * <p>
     * This method is only guaranteed to work <em>once</em>, the first time it
     * is invoked for a particular item. This is because, in the event that the
     * method renames a temporary file, that file will no longer be available
     * to copy or rename again at a later time.
     *
     * @param file The <code>File</code> into which the uploaded item should
     *             be stored.
     *
     * @throws Exception if an error occurs.
     */
    @Override
    public void write(File file) throws Exception {

        try {

            InputStream input;
            if (dfos.isInMemory()) {
                input = new ByteArrayInputStream(dfos.getData());
            } else {
                input = new FileInputStream(dfos.getFile());
            }

            try (FileOutputStream output = new FileOutputStream(file)) {
                input = new Crypto().decrypt(input, key);
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
     * collected, this method can be used to ensure that this is done at an
     * earlier time, thus preserving system resources.
     */
    @Override
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
    @Override
    public String getFieldName() {
        return fieldName;
    }

    /**
     * Sets the field name used to reference this file item.
     *
     * @param name The name of the form field.
     *
     * @see #getFieldName()
     *
     */
    @Override
    public void setFieldName(String name) {
        this.fieldName = name;
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
    @Override
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
    @Override
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
    @Override
    public OutputStream getOutputStream() throws IOException {
        return new Crypto().encrypt(dfos, key);
    }

    @Override
    public FileItemHeaders getHeaders() {
        return headers;
    }

    @Override
    public void setHeaders(FileItemHeaders headers) {
        this.headers = headers;
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
        return String.format("name=%s, StoreLocation=%s, size=%s bytes, isFormField=%s, FieldName=%s",
                getName(), dfos.getFile(), Long.valueOf(getSize()),
                Boolean.valueOf(isFormField()), getFieldName());
    }
}
