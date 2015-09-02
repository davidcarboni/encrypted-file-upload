package com.github.davidcarboni.thetrain.json;

import com.github.davidcarboni.cryptolite.Random;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Test for {@link Transaction}.
 */
public class TransactionTest {

    @Test
    public void shouldGenerateIdAndStartDateWhenInstantiated() throws Exception {

        // Given
        // A transaction
        Transaction transaction;

        // When
        // We instantiate
        transaction = new Transaction();

        // Then
        // A random ID should be generated and the start date should be set
        assertTrue(StringUtils.isNotBlank(transaction.id()));
        assertTrue(StringUtils.isNotBlank(transaction.startDate));
        assertEquals(Transaction.STARTED, transaction.status);
    }

    @Test
    public void shouldAddUri() throws Exception {

        // Given
        // A transaction and a URI info
        Transaction transaction = new Transaction();
        UriInfo uriInfo = new UriInfo("test");

        // When
        // We add the URI info to the Transaction
        transaction.addUri(uriInfo);

        // Then
        // We should have one URI info in the collection
        assertEquals(1, transaction.uris().size());
        assertEquals(Transaction.PUBLISHING, transaction.status);
    }

    @Test
    public void shouldAddUrisConcurrently() throws InterruptedException {

        // Given
        // A transaction and lots of URI infos
        final Transaction transaction = new Transaction();
        Set<UriInfo> uriInfos = new HashSet<>();
        for (int i = 0; i < 2000; i++) {
            uriInfos.add(new UriInfo("/" + Random.id()));
        }
        ExecutorService pool = Executors.newFixedThreadPool(100);

        // When
        // We add all the URI infos to the Transaction
        for (final com.github.davidcarboni.thetrain.json.UriInfo uriInfo : uriInfos) {
            pool.submit(new Runnable() {
                @Override
                public void run() {
                    transaction.addUri(uriInfo);
                }
            });
        }

        // Then
        // We should have added all URI infos to the Transaction and not lost any
        pool.shutdown();
        pool.awaitTermination(10, SECONDS);
        assertEquals(uriInfos.size(), transaction.uris().size());
        for (com.github.davidcarboni.thetrain.json.UriInfo uriInfo : transaction.uris()) {
            Assert.assertTrue(uriInfos.contains(uriInfo));
        }
    }

    @Test(expected = UnsupportedOperationException.class)
    public void shouldNotBeAbleToModifyUris() {

        // Given
        // A transaction
        Transaction transaction = new Transaction();
        transaction.addUri(new UriInfo("test"));

        // When
        // We attempt to modify the URIs
        transaction.uris().clear();

        // Then
        // We should get an exception
    }

    @Test
    public void shouldAddError() {

        // Given
        // A transaction and an error message
        Transaction transaction = new Transaction();
        String error = "test";

        // When
        // We add the error to the Transaction
        transaction.addError(error);

        // Then
        // We should have one error in the collection
        assertEquals(1, transaction.errors().size());
    }

    @Test
    public void shouldAddErrorsConcurrently() throws InterruptedException {

        // Given
        // A transaction and lots of error messages
        final Transaction transaction = new Transaction();
        List<String> errors = new ArrayList<>();
        for (int i = 0; i < 2000; i++) {
            errors.add(Random.id());
        }
        ExecutorService pool = Executors.newFixedThreadPool(100);

        // When
        // We add all the error messages to the Transaction
        for (final String error : errors) {
            pool.submit(new Runnable() {
                @Override
                public void run() {
                    transaction.addError(error);
                }
            });
        }

        // Then
        // We should have added all error messages to the Transaction and not lost any
        pool.shutdown();
        pool.awaitTermination(10, SECONDS);
        assertEquals(errors.size(), transaction.errors().size());
        for (String error : transaction.errors()) {
            Assert.assertTrue(errors.contains(error));
        }
    }

    @Test(expected = UnsupportedOperationException.class)
    public void shouldNotBeAbleToModifyErrors() {

        // Given
        // A transaction
        Transaction transaction = new Transaction();
        transaction.addError("test");

        // When
        // We attempt to modify the errors
        transaction.errors().clear();

        // Then
        // We should get an exception
    }

    @Test
    public void shouldCommitTransaction() {

        // Given
        // Transactions
        Transaction ok = new Transaction();
        Transaction error = new Transaction();

        // When
        // We flag the transactions as committed
        ok.commit(true);
        error.commit(false);

        // Then
        // We should have end dates and the expected status strings
        assertEquals(Transaction.COMMITTED, ok.status);
        assertEquals(Transaction.COMMIT_FAILED, error.status);
        assertTrue(StringUtils.isNotBlank(ok.endDate));
        assertTrue(StringUtils.isNotBlank(error.endDate));
    }

    @Test
    public void shouldRollBackTransaction() {

        // Given
        // Transactions
        Transaction ok = new Transaction();
        Transaction error = new Transaction();

        // When
        // We flag the transactions as rolled back
        ok.rollback(true);
        error.rollback(false);

        // Then
        // We should have end dates and the expected status strings
        assertEquals(Transaction.ROLLED_BACK, ok.status);
        assertEquals(Transaction.ROLLBACK_FAILED, error.status);
        assertTrue(StringUtils.isNotBlank(ok.endDate));
        assertTrue(StringUtils.isNotBlank(error.endDate));
    }
}