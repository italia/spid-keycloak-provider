package org.keycloak.broker.spid.tests;

import org.keycloak.broker.spid.SpidSAML2AuthnRequestBuilder;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class SpidSAML2AuthnRequestBuilderTest {


    @Test
    public void plainDestination_and_port() {
        SpidSAML2AuthnRequestBuilder ss2arb = new SpidSAML2AuthnRequestBuilder();

        String destination = "http://test.server.mock:8088";

        ss2arb.destination(destination);

        Document doc = ss2arb.toDocument();

        Node request_destination = doc.getFirstChild().getAttributes().getNamedItem("Destination");

        Assert.assertEquals("http://test.server.mock:8088", request_destination.getTextContent());
    }

    @Test
    public void plainDestination_and_port_https() {
        SpidSAML2AuthnRequestBuilder ss2arb = new SpidSAML2AuthnRequestBuilder();

        String destination = "https://test.server.mock:8488";

        ss2arb.destination(destination);

        Document doc = ss2arb.toDocument();

        Node request_destination = doc.getFirstChild().getAttributes().getNamedItem("Destination");

        Assert.assertEquals("https://test.server.mock:8488", request_destination.getTextContent());
    }

    @Test
    public void plainDestination() {
        SpidSAML2AuthnRequestBuilder ss2arb = new SpidSAML2AuthnRequestBuilder();

        String destination = "http://test.server.mock";

        ss2arb.destination(destination);

        Document doc = ss2arb.toDocument();

        Node request_destination = doc.getFirstChild().getAttributes().getNamedItem("Destination");

        Assert.assertEquals("http://test.server.mock", request_destination.getTextContent());
    }

    @Test
    public void plainDestination_https() {
        SpidSAML2AuthnRequestBuilder ss2arb = new SpidSAML2AuthnRequestBuilder();

        String destination = "https://test.server.mock";

        ss2arb.destination(destination);

        Document doc = ss2arb.toDocument();

        Node request_destination = doc.getFirstChild().getAttributes().getNamedItem("Destination");

        Assert.assertEquals("https://test.server.mock", request_destination.getTextContent());
    }

    @Test
    public void destinantionWithPath_and_port() {
        SpidSAML2AuthnRequestBuilder ss2arb = new SpidSAML2AuthnRequestBuilder();

        String destination = "http://test.server.mock:8088/sso";

        ss2arb.destination(destination);

        Document doc = ss2arb.toDocument();

        Node request_destination = doc.getFirstChild().getAttributes().getNamedItem("Destination");

        Assert.assertEquals("http://test.server.mock:8088/sso", request_destination.getTextContent());
    }

    @Test
    public void destinantionWithPath_and_port_https() {
        SpidSAML2AuthnRequestBuilder ss2arb = new SpidSAML2AuthnRequestBuilder();

        String destination = "https://test.server.mock:8488/sso";

        ss2arb.destination(destination);

        Document doc = ss2arb.toDocument();

        Node request_destination = doc.getFirstChild().getAttributes().getNamedItem("Destination");

        Assert.assertEquals("https://test.server.mock:8488/sso", request_destination.getTextContent());
    }

    @Test
    public void destinantionWithPath() {
        SpidSAML2AuthnRequestBuilder ss2arb = new SpidSAML2AuthnRequestBuilder();

        String destination = "http://test.server.mock/sso";

        ss2arb.destination(destination);

        Document doc = ss2arb.toDocument();

        Node request_destination = doc.getFirstChild().getAttributes().getNamedItem("Destination");

        Assert.assertEquals("http://test.server.mock/sso", request_destination.getTextContent());
    }

    @Test
    public void destinantionWithPath_https() {
        SpidSAML2AuthnRequestBuilder ss2arb = new SpidSAML2AuthnRequestBuilder();

        String destination = "https://test.server.mock/sso";

        ss2arb.destination(destination);
        
        Document doc = ss2arb.toDocument();

        Node request_destination = doc.getFirstChild().getAttributes().getNamedItem("Destination");

        Assert.assertEquals("https://test.server.mock/sso", request_destination.getTextContent());
    }
}
