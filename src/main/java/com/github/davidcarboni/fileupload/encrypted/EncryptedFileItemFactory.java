package com.github.davidcarboni.fileupload.encrypted;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;

public class EncryptedFileItemFactory implements FileItemFactory {
    @Override
    public FileItem createItem(String fieldName, String contentType, boolean isFormField, String fileName) {
        return null;
    }
}
