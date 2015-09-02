package com.github.davidcarboni.thetrain.storage;

import com.github.davidcarboni.cryptolite.Random;
import com.github.davidcarboni.thetrain.json.Transaction;
import com.github.davidcarboni.thetrain.json.UriInfo;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.*;

/**
 * Test for {@link Transactions}.
 */
public class TransactionsTest {

    /**
     * Tests that a transaction is created with an ID and start date and can be read using the ID.
     */
    @Test
    public void shouldCreateTransaction() throws IOException {

        // Given
        // No transaction yet

        // When
        // We create a transaction
        Transaction transaction = Transactions.create(null);

        // Then
        // The transaction should exist and be populated with values
        assertNotNull(transaction);
        assertTrue(StringUtils.isNotBlank(transaction.id()));
        assertTrue(StringUtils.isNotBlank(transaction.startDate()));
        assertNotNull(Transactions.get(transaction.id(), null));
    }

    /**
     * Tests that a transaction can be created with an encryption key.
     */
    @Test
    public void shouldCreateTransactionWithEncryption() throws IOException {

        // Given
        // An encryption password
        String password = Random.password(8);

        // When
        // We create a transaction
        Transaction transaction = Transactions.create(password);

        // Then
        // The transaction should exist and be populated with values
        assertNotNull(transaction.key());
    }

    /**
     * Tests that a collection is created with an ID and start date and can be read using the ID.
     */
    @Test
    public void shouldGetTransaction() throws IOException {

        // Given
        // A transaction
        Transaction transaction = Transactions.create(null);

        // When
        // We get the transaction
        Transaction got = Transactions.get(transaction.id(), null);

        // Then
        // The read transaction should contain the expected values:
        assertNotNull(got);
        assertEquals(transaction.id(), got.id());
        assertEquals(transaction.startDate(), got.startDate());
    }

    /**
     * Tests that a collection is created with an ID and start date and can be read using the ID.
     */
    @Test
    public void shouldUpdateTransaction() throws IOException {

        // Given
        // A transaction
        Transaction transaction = Transactions.create(null);
        UriInfo uriInfo = new UriInfo("/uri.txt");
        String error = "error";
        transaction.addError(error);
        transaction.addUri(uriInfo);

        // When
        // We update the transaction
        Transactions.update(transaction);

        // Then
        // Re-reading the Transaction should load the updates
        synchronized (Transactions.transactionMap) {
            // So we can run tests in parallel
            Transactions.transactionMap.clear();
        }
        Transaction read = Transactions.get(transaction.id(), null);
        assertEquals(1, read.errors().size());
        assertEquals(1, read.uris().size());
        assertTrue(read.errors().contains(error));
        assertTrue(read.uris().contains(uriInfo));
    }

    /**
     * Tests that a collection is created with an ID and start date and can be read using the ID.
     */
    @Test
    public void shouldUpdateTransactionConcurrently() throws IOException, InterruptedException {


        // Given
        // A transaction and lots of URI infos and errors
        final Transaction transaction = Transactions.create(null);
        Set<UriInfo> uriInfos = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            uriInfos.add(new UriInfo("/" + Random.id()));
        }
        Set<String> errors = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            errors.add("error " + Random.id());
        }
        ExecutorService pool = Executors.newFixedThreadPool(100);

        // When
        // We add all the URI infos and errors to the Transaction
        for (final com.github.davidcarboni.thetrain.json.UriInfo uriInfo : uriInfos) {
            pool.submit(new Runnable() {
                @Override
                public void run() {
                    transaction.addUri(uriInfo);
                    try {
                        //System.out.println("Updating "+UriInfo);
                        Transactions.update(transaction);
                    } catch (IOException e) {
                        System.out.println("Error adding URI info to transaction (" + uriInfo + ")");
                    }
                }
            });
        }
        for (final String error : errors) {
            pool.submit(new Runnable() {
                @Override
                public void run() {
                    transaction.addError(error);
                    try {
                        //System.out.println("Updating "+error);
                        Transactions.update(transaction);
                    } catch (IOException e) {
                        System.out.println("Error adding error to transaction (" + error + ")");
                    }
                }
            });
        }

        // Then
        // Wait for updates to complete
        pool.shutdown();
        pool.awaitTermination(10, SECONDS);

        // Clear the transaction map so we can double-check the Json serialised correctly when it's re-read:
        synchronized (Transactions.transactionMap) {
            // So we can run tests in parallel
            Transactions.transactionMap.clear();
        }

        // We should have added all URI infos to the Transaction and not lost any
        assertEquals(uriInfos.size(), transaction.uris().size());
        assertEquals(errors.size(), transaction.errors().size());
        for (com.github.davidcarboni.thetrain.json.UriInfo uriInfo : transaction.uris()) {
            Assert.assertTrue(uriInfos.contains(uriInfo));
        }
        for (String error : transaction.errors()) {
            Assert.assertTrue(error.contains(error));
        }
    }

    /**
     * Tests that a collection is created with an ID and start date and can be read using the ID.
     */
    @Test
    public void shouldNotGetNonexistentTransaction() throws IOException {

        // Given
        // A nonexistent transaction ID
        String id = "Not here, mate";

        // When
        // We get with the ID
        Transaction got = Transactions.get(id, null);

        // Then
        // We should get null and no error
        assertNull(got);
    }

    /**
     * Tests that a collection is created with an ID and start date and can be read using the ID.
     */
    @Test
    public void shouldHandleNullTransactionId() throws IOException {

        // Given
        // A null transaction ID
        String id = null;

        // When
        // We get with the ID
        Transaction got = Transactions.get(id, null);

        // Then
        // We should get null and no error
        assertNull(got);
    }

    @Test
    public void shouldGetContentPath() throws IOException {

        // Given
        // A transaction
        Transaction transaction = Transactions.create(null);

        // When
        // We get the content staging path
        Path content = Transactions.content(transaction);

        // Then
        // The transaction should contain a content directory:
        assertNotNull(content);
        assertTrue(Files.exists(content));
        assertTrue(Files.isDirectory(content));
        assertEquals(Transactions.CONTENT, content.getFileName().toString());
    }

    @Test
    public void shouldNotGetNonexistentContentPath() throws IOException {

        // Given
        // A nonexistent transaction ID (ie not created on disk)
        Transaction transaction = new Transaction();

        // When
        // We get the content staging path
        Path content = Transactions.content(transaction);

        // Then
        // We should get null and no error
        assertNull(content);
    }

    @Test
    public void shouldGetBackupPath() throws IOException {

        // Given
        // A transaction
        Transaction transaction = Transactions.create(null);

        // When
        // We get the backup path
        Path backup = Transactions.backup(transaction);

        // Then
        // The transaction should contain a content directory:
        assertNotNull(backup);
        assertTrue(Files.exists(backup));
        assertTrue(Files.isDirectory(backup));
        assertEquals(Transactions.BACKUP, backup.getFileName().toString());
    }

    @Test
    public void shouldNotGetNonexistentBackupPath() throws IOException {

        // Given
        // A nonexistent transaction ID (ie not created on disk)
        Transaction transaction = new Transaction();

        // When
        // We get the backup path
        Path backup = Transactions.backup(transaction);

        // Then
        // We should get null and no error
        assertNull(backup);
    }

}