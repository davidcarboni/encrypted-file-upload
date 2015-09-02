package com.github.davidcarboni.thetrain.helpers;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.*;

/**
 * Test for {@link PathUtils}.
 */
public class PathUtilsTest {

    Path tempFolder;

    @Before
    public void beforeTest() throws IOException {
        tempFolder = Files.createTempDirectory(this.getClass().getSimpleName());
    }

    @Test
    public void shouldFindContainedPath() throws IOException {

        // Given
        // A contained folder
        Path container = folder("container");
        Path contained = folder("container/sub/folder");
        Files.createDirectories(contained);

        // When
        // We check if the path is contained
        boolean result = PathUtils.isContained(contained, container);

        // Then
        // The answer should be yes
        assertTrue(result);
    }

    @Test
    public void shouldNotFindNotContainedPath() throws IOException {

        // Given
        // A contained folder
        Path container = folder("container");
        Path contained = folder("some/other/folder");

        // When
        // We check if the path is contained
        boolean result = PathUtils.isContained(contained, container);

        // Then
        // The answer should be yes
        assertFalse(result);
    }

    @Test
    public void shouldNotFindNotContainedRelativePath() throws IOException {

        // Given
        // A contained folder
        Path container = folder("container");
        Path contained = folder("container/../parent/level/folder");

        // When
        // We check if the path is contained
        boolean result = PathUtils.isContained(contained, container);

        // Then
        // The answer should be yes
        assertFalse(result);
    }

    @Test
    public void shouldNotFindDodgyRelativePath() throws IOException {

        // Given
        // A contained folder
        Path container = folder("series/of/folders");
        Path contained = folder("series/of/folders/.././././../../dodgy/relative/path");

        // When
        // We check if the path is contained
        boolean result = PathUtils.isContained(contained, container);

        // Then
        // The answer should be yes
        assertFalse(result);
    }

    @Test
    public void shouldComputePath() throws IOException {

        // Given
        // A directory and a URI in that directory
        Path container = folder("parent");
        String uri = "/child";

        // When
        // We convert the URI to a path within the directory
        Path path = PathUtils.toPath(uri, container);

        // Then
        // The path should be within the parent directory
        assertEquals(container.resolve("child"), path);
    }

    @Test
    public void shouldComputeUri() throws IOException {

        // Given
        // A contained folder
        Path container = folder("parent");
        Path contained = folder("parent/child");

        // When
        // We check if the path is contained
        String uri = PathUtils.toUri(contained, container);

        // Then
        // The answer should be yes
        assertEquals("/child", uri);
    }

    @Test
    public void shouldReturnNullUriIfNotContained() throws IOException {

        // Given
        // A contained folder
        Path container = folder("parent");
        Path contained = folder("other/folder");

        // When
        // We check if the path is contained
        String uri = PathUtils.toUri(contained, container);

        // Then
        // The answer should be yes
        assertNull(uri);
    }

    @Test
    public void shouldStripLeadingSlash() throws IOException {

        // Given
        // A variety of path strings
        String leadingSlash = "/folder";
        String leadingSlashes = "///folder";
        String noLeadingSlash = "folder";
        String slash = "/";
        String empty = "";
        String nul = null;

        // When
        // We process the paths
        String leadingSlashResult = PathUtils.stripLeadingSlash(leadingSlash);
        String leadingSlashesResult = PathUtils.stripLeadingSlash(leadingSlashes);
        String noLeadingSlashResult = PathUtils.stripLeadingSlash(noLeadingSlash);
        String slashResult = PathUtils.stripLeadingSlash(slash);
        String emptyResult = PathUtils.stripLeadingSlash(empty);
        String nulResult = PathUtils.stripLeadingSlash(nul);

        // Then
        // We should get any slashes stripped
        assertEquals("folder", leadingSlashResult);
        assertEquals("folder", leadingSlashesResult);
        assertEquals("folder", noLeadingSlashResult);
        assertEquals("", slashResult);
        assertEquals("", emptyResult);
        assertEquals(null, nulResult);
    }

    @Test
    public void shouldSetLeadingSlash() throws IOException {

        // Given
        // A variety of path strings
        String leadingSlash = "/folder";
        String noLeadingSlash = "folder";
        String slash = "/";
        String empty = "/";
        String nul = null;

        // When
        // We process the paths
        String leadingSlashResult = PathUtils.setLeadingSlash(leadingSlash);
        String noLeadingSlashResult = PathUtils.setLeadingSlash(noLeadingSlash);
        String slashResult = PathUtils.setLeadingSlash(slash);
        String emptyResult = PathUtils.setLeadingSlash(empty);
        String nulResult = PathUtils.setLeadingSlash(nul);

        // Then
        // We should get any slashes stripped
        assertEquals("/folder", leadingSlashResult);
        assertEquals("/folder", noLeadingSlashResult);
        assertEquals("/", slashResult);
        assertEquals("/", emptyResult);
        assertEquals(null, nulResult);
    }

    private Path folder(String path) throws IOException {
        Path result = tempFolder.resolve(path);
        Files.createDirectories(result);
        return result;
    }

}