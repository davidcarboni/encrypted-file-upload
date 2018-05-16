package com.github.davidcarboni.fileupload.encrypted;

import java.io.File;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;

/**
 * <p>The default {@link org.apache.commons.fileupload.FileItemFactory}
 * implementation. This implementation creates
 * {@link org.apache.commons.fileupload.FileItem} instances which keep their
 * content either in memory, for smaller items, or in a temporary file on disk,
 * for larger items. The size threshold, above which content will be stored on
 * disk, is configurable, as is the directory in which temporary files will be
 * created.</p>
 *
 * <p>If not otherwise configured, the default configuration values are as
 * follows:</p>
 * <ul>
 *   <li>Size threshold is 10KB.</li>
 *   <li>Repository is the system default temp directory, as returned by
 *       <code>System.getProperty("java.io.tmpdir")</code>.</li>
 * </ul>
 * <p>
 * <b>NOTE</b>: Files are created in the system default temp directory.
 * This means that a local attacker with write access to that
 * directory can perform a TOUTOC attack to replace any uploaded file with a
 * file of the attackers choice. The attack is limited because data are encrypted
 * on disk, however bear in mind that AES encryption is "malleable" (see
 * <a href="https://en.wikipedia.org/wiki/Malleability_(cryptography)">
 *     https://en.wikipedia.org/wiki/Malleability_(cryptography)</a>) so there
 * will always be a level of risk. The implications of this will depend on how the
 * uploaded file is used but could be significant. When using this
 * implementation in an environment with local, untrusted users,
 * {@link #setRepository(File)} should be used to configure a repository location
 * that is not publicly writable. In a Servlet container the location identified
 * by the ServletContext attribute <code>javax.servlet.context.tempdir</code>
 * may be used.
 * </p>
 *
 * <p>Temporary files, which are created for file items, are automatically
 * deleted when the <code>finalize()</code> method of {@link EncryptedFileItem}
 * is called.</p>
 */
public class EncryptedFileItemFactory implements FileItemFactory {

    /**
     * The default threshold above which uploads will be stored on disk.
     */
    public static final int DEFAULT_SIZE_THRESHOLD = 10240;

    /**
     * The directory in which uploaded files will be stored, if stored on disk.
     */
    private File repository;

    /**
     * The threshold above which uploads will be stored on disk.
     */
    private int sizeThreshold = DEFAULT_SIZE_THRESHOLD;

    /**
     * Default content charset to be used when no explicit charset
     * parameter is provided by the sender.
     */
    private String defaultCharset;


    // ----------------------------------------------------------- Constructors

    /**
     * Constructs an unconfigured instance of this class. The resulting factory
     * may be configured by calling the appropriate setter methods.
     */
    public EncryptedFileItemFactory() {
        this(DEFAULT_SIZE_THRESHOLD, null);
    }

    /**
     * Constructs a preconfigured instance of this class.
     *
     * @param sizeThreshold The threshold, in bytes, below which items will be
     *                      retained in memory and above which they will be
     *                      stored as a file.
     * @param repository    The data repository, which is the directory in
     *                      which files will be created, should the item size
     *                      exceed the threshold. If this is null, FileItems
     *                      will default to using "java.io.tmpdir".
     */
    public EncryptedFileItemFactory(int sizeThreshold, File repository) {
        this.sizeThreshold = sizeThreshold;
        this.repository = repository;
    }

    // ------------------------------------------------------------- Properties

    /**
     * Returns the directory used to temporarily store files that are larger
     * than the configured size threshold.
     *
     * @return The directory in which temporary files will be located.
     *
     * @see #setRepository(java.io.File)
     *
     */
    public File getRepository() {
        return repository;
    }

    /**
     * Sets the directory used to temporarily store files that are larger
     * than the configured size threshold.
     *
     * @param repository The directory in which temporary files will be located.
     *
     * @see #getRepository()
     *
     */
    public void setRepository(File repository) {
        this.repository = repository;
    }

    /**
     * Returns the size threshold beyond which files are written directly to
     * disk. The default value is 10240 bytes.
     *
     * @return The size threshold, in bytes.
     *
     * @see #setSizeThreshold(int)
     */
    public int getSizeThreshold() {
        return sizeThreshold;
    }

    /**
     * Sets the size threshold beyond which files are written directly to disk.
     *
     * @param sizeThreshold The size threshold, in bytes.
     *
     * @see #getSizeThreshold()
     *
     */
    public void setSizeThreshold(int sizeThreshold) {
        this.sizeThreshold = sizeThreshold;
    }

    // --------------------------------------------------------- Public Methods

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
        return new EncryptedFileItem(fieldName, contentType,
                isFormField, fileName, sizeThreshold, repository, defaultCharset);
    }

    /**
     * Returns the default charset for use when no explicit charset
     * parameter is provided by the sender.
     * @return the default charset
     */
    public String getDefaultCharset() {
        return defaultCharset;
    }

    /**
     * Sets the default charset for use when no explicit charset
     * parameter is provided by the sender.
     * @param charset the default charset
     */
    public void setDefaultCharset(String charset) {
        defaultCharset = charset;
    }
}
