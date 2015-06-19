package org.owasp.appsensor;

import java.util.Arrays;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = AppsensorUiApplication.class)
@WebAppConfiguration
@IntegrationTest("server.port=0")
@DirtiesContext
public class AppsensorUiApplicationTests {

	@Value("${local.server.port}")
	private int port;

	@Test
	public void testMustacheTemplate() throws Exception {
		ResponseEntity<String> entity = new TestRestTemplate().getForEntity(
				"http://localhost:" + this.port, String.class);
		assertEquals(HttpStatus.OK, entity.getStatusCode());
		assertTrue("Wrong body:\n" + entity.getBody(),
				entity.getBody().contains("Hello, Andy"));
	}

	@Test
	public void testMustacheErrorTemplate() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		HttpEntity<String> requestEntity = new HttpEntity<String>(headers);

		ResponseEntity<String> responseEntity = new TestRestTemplate().exchange(
				"http://localhost:" + this.port + "/does-not-exist", HttpMethod.GET,
				requestEntity, String.class);

		assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
		assertTrue("Wrong body:\n" + responseEntity.getBody(), responseEntity.getBody()
				.contains("Something went wrong: 404 Not Found"));
	}

}