# Encrypted HTTP Multipart Upload

Implementations of Commons Fileupload 'FileItemFactory' and 'FileItem' that provide transparent encryption of file uploads if they get cached on disk as temporary files.


## Basics

These classes are drop-in replacements for 'org.apache.commons.fileupload.disk.DiskFileItemFactory' and 'org.apache.commons.fileupload.disk.DiskFileItem'.

Encryption is transparent and you should need to make no change to your code.

The sole purpose of these classes is to ensure that data are not written to disk in the clear 


## Encryption

Encryption is provided by your standard JCE providers, via the [Cryptolite](https://github.com/davidcarboni/Cryptolite) library.

If you have any concerns, feel free to inspect / copy / replace the JCE code from Cryptolite.

Encryption keys are generated at random and held in memory when the above classes are instantiated.

