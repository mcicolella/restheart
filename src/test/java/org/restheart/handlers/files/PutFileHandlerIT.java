package org.restheart.handlers.files;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.UUID;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import static org.restheart.hal.Representation.HAL_JSON_MEDIA_TYPE;
import static org.restheart.utils.HttpStatus.SC_CREATED;
import static org.restheart.utils.HttpStatus.SC_OK;

/**
 * TODO: fillme
 */
public class PutFileHandlerIT extends FileHandlerAbstractIT {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @Before
    public void init() throws Exception {
        createBucket();
    }

    private HttpResponse createFilePut(String id) throws UnknownHostException, IOException {
        String bucketUrl = dbTmpUri + "/" + BUCKET + ".files/" + id;

        HttpEntity entity = buildMultipartResource();

        Response resp = adminExecutor.execute(Request.Put(bucketUrl)
                .body(entity));

        HttpResponse httpResp = resp.returnResponse();
        assertNotNull(httpResp);
        StatusLine statusLine = httpResp.getStatusLine();
        assertNotNull(statusLine);

        assertTrue("check status code", Arrays.asList(SC_CREATED, SC_OK).contains(statusLine.getStatusCode()));

        return httpResp;
    }

    @Test
    public void testPutNonExistingFile() throws IOException {
        String id = "nonexistingfile" + UUID.randomUUID().toString();

        final HttpResponse httpResponse = createFilePut(id);
        assertEquals(SC_CREATED, httpResponse.getStatusLine().getStatusCode());

        // test that GET /db/bucket.files includes the file
        final String fileUrl = dbTmpUri + "/" + BUCKET + ".files/" + id;
        Response resp = adminExecutor.execute(Request.Get(fileUrl));

        HttpResponse httpResp = this.check("Response is 200 OK", resp, SC_OK);
        HttpEntity entity = checkContentType(httpResp, HAL_JSON_MEDIA_TYPE);
        checkNotNullMetadata(entity);
    }

    @Test
    public void testPutAndOverwriteExistingFile() throws IOException {
        String id = "nonexistingfile" + UUID.randomUUID().toString();

        HttpResponse httpResponse = createFilePut(id);
        assertEquals(SC_CREATED, httpResponse.getStatusLine().getStatusCode());
        //now run the put again to see that it has been overwritten
        httpResponse = createFilePut(id);
        assertEquals(SC_OK, httpResponse.getStatusLine().getStatusCode());

        // test that GET /db/bucket.files includes the file
        final String fileUrl = dbTmpUri + "/" + BUCKET + ".files/" + id;
        Response resp = adminExecutor.execute(Request.Get(fileUrl));

        HttpResponse httpResp = this.check("Response is 200 OK", resp, SC_OK);
        HttpEntity entity = checkContentType(httpResp, HAL_JSON_MEDIA_TYPE);
        checkNotNullMetadata(entity);
    }
}