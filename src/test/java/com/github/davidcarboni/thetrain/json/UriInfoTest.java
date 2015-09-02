package com.github.davidcarboni.thetrain.json;

import com.github.davidcarboni.thetrain.helpers.DateConverter;
import org.junit.Assert;
import org.junit.Test;

import java.util.Date;

/**
 * Test for {@link UriInfo}.
 */
public class UriInfoTest {

    @Test
    public void shouldSetStartDateUriAndStatusOnInstantiation() throws InterruptedException {

        // Given
        String uri = "/uri";

        // When
        UriInfo uriInfo = new UriInfo(uri, new Date());

        // Then
        Assert.assertNotNull(uriInfo.startDate);
        Assert.assertEquals(uriInfo.startDate, DateConverter.toDate(uriInfo.start));
        Assert.assertNull(uriInfo.endDate);
        Assert.assertEquals(uriInfo.duration, 0);
        Assert.assertEquals(UriInfo.STARTED, uriInfo.status);
    }

    @Test
    public void shouldSetEndDateDurationShaAndStatusOnStop() throws InterruptedException {

        // Given
        String sha = "123abc";
        UriInfo uriInfo = new UriInfo("test", new Date());
        Thread.sleep(2);

        // When
        uriInfo.stop(sha, 0);

        // Then
        Assert.assertNotNull(uriInfo.endDate);
        Assert.assertEquals(uriInfo.endDate, DateConverter.toDate(uriInfo.end));
        Assert.assertTrue(uriInfo.duration > 0);
        Assert.assertEquals(sha, uriInfo.sha);
        Assert.assertEquals(UriInfo.UPLOADED, uriInfo.status);
    }

    @Test
    public void shouldNotUpdateStatusForBlankSha() throws InterruptedException {

        // Given
        UriInfo blank = new UriInfo("blank", new Date());
        UriInfo nul = new UriInfo("null", new Date());

        // When
        blank.stop("", 0);
        nul.stop(null, 0);

        // Then
        Assert.assertEquals("upload failed", blank.status);
        Assert.assertEquals("upload failed", nul.status);
    }

    @Test
    public void shouldCommit() throws InterruptedException {

        // Given
        UriInfo uriInfo = new UriInfo("uri");

        // When
        uriInfo.commit(UriInfo.UPDATE);

        // Then
        Assert.assertEquals(UriInfo.COMMITTED, uriInfo.status);
        Assert.assertEquals(UriInfo.UPDATE, uriInfo.action);
    }

    @Test
    public void shouldFail() throws InterruptedException {

        // Given
        UriInfo uriInfo = new UriInfo("uri");
        String error = "error";

        // When
        uriInfo.fail(error);

        // Then
        Assert.assertEquals(UriInfo.COMMIT_FAILED, uriInfo.status);
        Assert.assertEquals(error, uriInfo.error);
    }

    @Test
    public void shouldEvaluateEquality() throws InterruptedException {

        // Given
        // URIs that are and are not equal
        UriInfo compare = new UriInfo("/uri");
        UriInfo equal = new UriInfo("/uri");
        UriInfo notEqual = new UriInfo("/other");

        // When
        // We test equality
        boolean equalResult = compare.equals(equal);
        boolean notEqualResult = compare.equals(notEqual);

        // Then
        // We should get equal/not equal as expected
        Assert.assertTrue(equalResult);
        Assert.assertFalse(notEqualResult);
    }
}