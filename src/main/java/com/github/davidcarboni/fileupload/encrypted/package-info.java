/**
 *    <p>
 *      A disk-based implementation of the
 *      {@link org.apache.commons.fileupload.FileItem FileItem}
 *      interface, providing transparent encryption with ephemeral keys.
 *      This implementation retains smaller items in memory, while
 *      writing larger ones to disk. The threshold between these two is
 *      configurable, as is the location of files that are written to disk.
 *    </p>
 *    <p>
 *      In typical usage, an instance of
 *      {@link com.github.davidcarboni.fileupload.encrypted.EncryptedFileItemFactory EncryptedFileItemFactory}
 *      would be created, configured, and then passed to a
 *      {@link org.apache.commons.fileupload.FileUpload FileUpload}
 *      implementation such as
 *      {@link org.apache.commons.fileupload.servlet.ServletFileUpload ServletFileUpload}
 *      or
 *      {@link org.apache.commons.fileupload.portlet.PortletFileUpload PortletFileUpload}.
 *    </p>
 *    <p>
 *      The following code fragment demonstrates this usage.
 *    </p>
 * <pre>
 *        EncryptedFileItemFactory factory = new EncryptedFileItemFactory();
 *        // maximum size that will be stored in memory
 *        factory.setSizeThreshold(4096);
 *        // the location for saving data that is larger than getSizeThreshold()
 *        factory.setRepository(new File("/tmp"));
 *
 *        ServletFileUpload upload = new ServletFileUpload(factory);
 * </pre>
 *    <p>
 *      Please see the FileUpload
 *      <a href="http://commons.apache.org/fileupload/using.html" target="_top">User Guide</a>
 *      for further details and examples of how to use the interfaces.
 *    </p>
 */
package com.github.davidcarboni.fileupload.encrypted;
