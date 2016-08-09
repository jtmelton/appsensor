package org.owasp.appsensor.storage.elasticsearch;

import com.google.common.io.Files;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.NodeBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.Properties;

/**
 * Test configuration for elastic search storage testing
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */
@Configuration
@ComponentScan("org.owasp.appsensor")
public class ElasticTestConfiguration {

    private static int elasticTcpPort;
    private static int elasticHttpPort;

    static {
        try {
            elasticTcpPort = new ServerSocket(0).getLocalPort();
            elasticHttpPort = new ServerSocket(0).getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    private Node node;

    @PostConstruct
    private void postConstruct() throws IOException {
        Settings settings = Settings.settingsBuilder()
                .put("path.home", Files.createTempDir().getAbsolutePath())
                .put("transport.tcp.port", elasticTcpPort)
                .put("http.port", elasticHttpPort)
                .build();
        node = NodeBuilder.nodeBuilder().settings(settings).node();
        node.start();

        System.out.println("ELASTIC HTTP MAIK : " + elasticHttpPort);

    }

    @PreDestroy
    private void preDestroy() {
        node.close();
    }


    /**
     * Property placeholder configurer needed to process @Value annotations
     */
    @Bean
    public static PropertySourcesPlaceholderConfigurer propertyConfigurer() {
        return new PropertySourcesPlaceholderConfigurer() {
            @Override
            protected void loadProperties(Properties props) throws IOException {
                super.loadProperties(props);
                props.put("appsensor.elasticsearch.indexname", "appsensortest");
                props.put("appsensor.elasticsearch.host", "127.0.0.1");

                props.put("appsensor.elasticsearch.port", elasticTcpPort);
                props.put("appsensor.elasticsearch.clustername", "elasticsearch");

            }
        };
    }
}
