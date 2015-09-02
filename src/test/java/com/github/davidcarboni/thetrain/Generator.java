package com.github.davidcarboni.thetrain;

import com.github.davidcarboni.cryptolite.Random;
import com.github.davidcarboni.thetrain.json.Transaction;
import com.github.davidcarboni.thetrain.storage.Publisher;
import com.github.davidcarboni.thetrain.storage.Transactions;
import com.github.davidcarboni.thetrain.storage.Website;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.exception.ExceptionUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Class for generating random folders and content.
 */
public class Generator {

    public static Path generate() throws IOException {
        Path thetrain = Files.createTempDirectory("thetrain");
        generate(thetrain);
        return thetrain;
    }

    static void generate(Path path) throws IOException {

        ExecutorService pool = Executors.newCachedThreadPool();
        generateFiles(path, pool);
        generateFolders(path, pool);
        pool.shutdown();
        try {
            pool.awaitTermination(60, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            throw new RuntimeException("Error generating files", e);
        }
    }

    static void generateFolders(Path path, ExecutorService pool) throws IOException {

        // Generate some folders
        for (int folders = 0; folders < random(); folders++) {
            Path folder = path.resolve(name());
            Files.createDirectory(folder);
            generateFiles(folder, pool);
        }
    }

    static void generateFiles(final Path path, ExecutorService pool) throws IOException {

        // Generate some files
        for (int files = 0; files < random() + 10; files++) {
            final int count = files;
            pool.submit(new Runnable() {
                @Override
                public void run() {

                    Path file = path.resolve(name() + ".txt");
                    // Generate a range of file sizes that don't fall on simple buffer-size boundaries:
                    int size = (int) (Math.abs((int) Math.pow(2, count)) * 100) + (random() * 17);

                    try (OutputStream output = Files.newOutputStream(file); InputStream input = Random.inputStream(size)) {
                        IOUtils.copy(input, output);
                        System.out.println("Generated a file of size " + size);
                    } catch (IOException e) {
                        System.out.println(ExceptionUtils.getStackTrace(e));
                        ;
                    }
                }
            });

        }
    }

    /**
     * @return A random number between 5 and 10.
     */
    static int random() {
        double random = Math.random();
        return (int) ((random * 6) + 5);
    }

    static String name() {
        return com.github.davidcarboni.cryptolite.Random.password(random());
    }

    static String content() {
        return com.github.davidcarboni.cryptolite.Random.password(random() * 1000) + "\n";
    }


    /**
     * Manual test of the commit functionality.
     *
     * @param args Not used.
     * @throws IOException If an error occurs.
     */
    public static void main(String[] args) throws IOException {

        // Generate a Transaction containing some content
        Transaction transaction = Transactions.create(null);
        System.out.println("Transaction: " + Transactions.content(transaction).getParent());
        Path generated = Generator.generate();
        System.out.println("Generated: " + generated);
        Files.move(generated, Transactions.content(transaction), StandardCopyOption.REPLACE_EXISTING);
        System.out.println("Moved to: " + Transactions.content(transaction));

        // Simulate the content already being on the website
        //Files.delete(Website.path());
        FileUtils.copyDirectory(Transactions.content(transaction).toFile(), Website.path().toFile());

        // Attempt to commit
        Publisher.commit(transaction, com.github.davidcarboni.thetrain.storage.Website.path());
        System.out.println("Committed to " + Website.path());

        // Print out
        System.out.println();
        System.out.println("Content : " + Transactions.content(transaction));
        System.out.println("Website : " + Website.path());
        System.out.println("Backup  : " + Transactions.backup(transaction));
    }
}
