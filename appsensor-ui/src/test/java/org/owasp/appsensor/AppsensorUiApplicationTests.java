package org.owasp.appsensor;


//@RunWith(SpringJUnit4ClassRunner.class)
//@SpringApplicationConfiguration(classes = AppsensorUiApplication.class)
//@WebAppConfiguration
//@IntegrationTest("server.port=0")
//@DirtiesContext
public class AppsensorUiApplicationTests {

//	@Value("${local.server.port}")
//	private int port;

//	@Test
//	public void testMustacheTemplate() throws Exception {
//		ResponseEntity<String> entity = new TestRestTemplate().getForEntity(
//				"http://localhost:" + this.port, String.class);
//		assertEquals(HttpStatus.OK, entity.getStatusCode());
//		assertTrue("Wrong body:\n" + entity.getBody(),
//				entity.getBody().contains("Hello, Andy"));
//	}
//
//	@Test
//	public void testMustacheErrorTemplate() throws Exception {
//		HttpHeaders headers = new HttpHeaders();
//		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
//		HttpEntity<String> requestEntity = new HttpEntity<String>(headers);
//
//		ResponseEntity<String> responseEntity = new TestRestTemplate().exchange(
//				"http://localhost:" + this.port + "/does-not-exist", HttpMethod.GET,
//				requestEntity, String.class);
//
//		assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
//		assertTrue("Wrong body:\n" + responseEntity.getBody(), responseEntity.getBody()
//				.contains("Something went wrong: 404 Not Found"));
//	}

}