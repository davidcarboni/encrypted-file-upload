# Encrypted HTTP Multipart Upload

Implementations of [Commons Fileupload](https://github.com/apache/commons-fileupload) 
['FileItemFactory'](https://github.com/apache/commons-fileupload/blob/master/src/main/java/org/apache/commons/fileupload/FileItemFactory.java)
and ['FileItem'](https://github.com/apache/commons-fileupload/blob/master/src/main/java/org/apache/commons/fileupload/FileItem.java) 
that provide transparent encryption of file uploads for the lifetime of a 'FileItem'.

This implementation is designed to be transparent to the caller. 
Keys are ephemeral and are generated on the fly, so encryption "just works" without you needing to do anything.

When the 'FileItem' is garbage collected, the key is lost and any temp data becomes unrecoverable 
(*that's a good thing*). 

The purpose of this implementation is to make it trivial to ensure uploaded data are not written to disk in the clear.

For more discussion, see the Apache Commons FileUpload Jira: 
https://issues.apache.org/jira/browse/FILEUPLOAD-119


## Basics

These classes are designed as drop-in replacements for 
['DiskFileItemFactory'](https://github.com/apache/commons-fileupload/blob/master/src/main/java/org/apache/commons/fileupload/disk/DiskFileItemFactory.java) 
and ['DiskFileItem'](https://github.com/apache/commons-fileupload/blob/master/src/main/java/org/apache/commons/fileupload/disk/DiskFileItem.java).

Encryption is transparent and you should need to make no change to your code, providing you stick to the 
['FileItem'](https://github.com/apache/commons-fileupload/blob/master/src/main/java/org/apache/commons/fileupload/FileItem.java) interface.

Dependency:

```xml
<dependency>
  <groupId>com.github.davidcarboni</groupId>
  <artifactId>encrypted-file-upload</artifactId>
  <version>2.0.0</version>
</dependency>
```

Usage:

```java
// Create a factory for disk-based file items
FileItemFactory factory = new EncryptedFileItemFactory();

// Create a new file upload handler
ServletFileUpload upload = new ServletFileUpload(factory);

// Parse the request
List<FileItem> items = upload.parseRequest(request);
```

For more on FileUpload usage, see: https://commons.apache.org/proper/commons-fileupload/using.html

NB there's less of a need to call `factory.setRepository(...)`
because content written to disk is encrypted.

If you rely on the additional method 'getStoreLocation()' provided by the
['DiskFileItem'](https://github.com/apache/commons-fileupload/blob/master/src/main/java/org/apache/commons/fileupload/disk/DiskFileItem.java) 
implementation, you'll need to alter your code to use 'getInputStream()' instead. 

The reason for this is that the raw temp file is encrypted: *the centent is meaningless*.
Directly accessing this file (for example to move it rather than copy it)
would lead to unexpected results (ie a scrambled file). 
The 'getStoreLocation()' method is not provided to help you avoid this happening unintentionally. 


## Testing

A note on how these classes have been tested.
The Commons FileUpload test suite has been copied
into this project in its entirety. 
It's then been tweaked just enough to point the tests
at `EncryptedFileItem` and `EncryptedFileItemFactory`.
This ensures that these implementations pass the same 
standard of tests as the implementations in FileUpload.


## Encryption

Encryption is provided by your standard JCE providers, via the [Cryptolite](https://github.com/davidcarboni/Cryptolite) library.

Data are encrypted using AES-128 in Counter (CTR) mode.
This should ensure compatibility with the majority of JVMs.

If you would like to look in detail at the encryption code, feel free to inspect, copy or replace the JCE code from Cryptolite.

Encryption keys are generated at random and held in memory when the above classes are instantiated.
Keys are lost when the objects are garbage-collected.

Strictly speaking, no security solution is perfect. 
However, these classes provide specific risk reduction,
relative to working with cleartext temp files.

*If this is something you need* then this implementation is for you.
