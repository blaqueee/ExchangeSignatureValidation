package com.customs;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.*;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Iterator;

/**
 * Класс для обработки XML-подписей, включая парсинг, канонизацию и верификацию.
 * Ответственность: вся логика, не связанная с UI.
 */
class XmlSignatureProcessor {

    static {
        // Инициализация библиотеки Apache Santuario.
        Init.init();
    }

    /**
     * Создает фабрику построителя документов с учетом пространств имен.
     * @return Настроенная DocumentBuilderFactory.
     */
    private static DocumentBuilderFactory createDocumentBuilderFactory() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true); // Важно: оставляем true для начального парсинга SOAP
        dbf.setIgnoringElementContentWhitespace(false);
        return dbf;
    }

    /**
     * Создает построитель документов.
     * @return DocumentBuilder.
     * @throws ParserConfigurationException если возникла ошибка конфигурации парсера.
     */
    private static DocumentBuilder createDocumentBuilder() throws ParserConfigurationException {
        return createDocumentBuilderFactory().newDocumentBuilder();
    }

    /**
     * Создает фабрику XPath.
     * @return XPathFactory.
     */
    private static XPathFactory createXPathFactory() {
        return XPathFactory.newInstance();
    }

    /**
     * Создает и настраивает NamespaceContext для SOAP-пространства имен.
     * @return NamespaceContext.
     */
    private static NamespaceContext createSoapNamespaceContext() {
        return new NamespaceContext() {
            @Override
            public String getNamespaceURI(String prefix) {
                if ("soap".equals(prefix)) {
                    return "http://www.w3.org/2001/06/soap-envelope";
                }
                return null;
            }
            @Override
            public String getPrefix(String uri) { return null; }
            @Override
            public Iterator<String> getPrefixes(String uri) { return null; }
        };
    }

    /**
     * Извлекает Base64-строку подписи из SOAP Header XML.
     * @param fullSoapXml Полный XML-документ SOAP.
     * @return Base64-строка подписи.
     * @throws Exception Если элемент подписи не найден или ошибка парсинга.
     */
    public static String extractSignatureBase64(String fullSoapXml) throws Exception {
        Document doc = createDocumentBuilder().parse(new ByteArrayInputStream(fullSoapXml.getBytes(StandardCharsets.UTF_8)));
        XPath xpath = createXPathFactory().newXPath();
        xpath.setNamespaceContext(createSoapNamespaceContext());

        String signatureBase64 = xpath.evaluate("/soap:Envelope/soap:Header/Signature", doc).trim();
        if (signatureBase64.isEmpty()) {
            throw new Exception("Signature element not found in SOAP Header at /soap:Envelope/soap:Header/Signature");
        }
        return signatureBase64;
    }

    /**
     * Возвращает LSSerializer, настроенный для имитации Exchange XmlDocument.OuterXml.
     * @return LSSerializer.
     * @throws ClassNotFoundException если DOMImplementationLS не найден.
     * @throws InstantiationException если DOMImplementationLS не может быть инстанцирован.
     * @throws IllegalAccessException если DOMImplementationLS недоступен.
     * @throws ClassCastException если не может быть приведен к DOMImplementationLS.
     */
    private static LSSerializer getLSSerializer() throws ClassNotFoundException, InstantiationException, IllegalAccessException, ClassCastException {
        DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
        DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
        LSSerializer serializer = impl.createLSSerializer();
        serializer.getDomConfig().setParameter("xml-declaration", Boolean.FALSE);
        serializer.getDomConfig().setParameter("format-pretty-print", Boolean.FALSE);
        return serializer;
    }

    /**
     * Рекурсивно удаляет пространства имен из узла и его потомков.
     * Создает новые узлы без префиксов и атрибутов xmlns.
     * @param node Исходный узел.
     * @param document Документ, к которому будут принадлежать новые узлы.
     * @return Новый узел без пространств имен.
     */
    private static Node removeNamespacesRecursive(Node node, Document document) {
        if (node.getNodeType() == Node.ELEMENT_NODE) {
            Element newElement = document.createElement(node.getLocalName());

            NamedNodeMap attributes = node.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                Node attr = attributes.item(i);
                if (!attr.getNodeName().startsWith("xmlns") && attr.getNamespaceURI() == null) {
                    newElement.setAttribute(attr.getLocalName(), attr.getNodeValue());
                }
            }

            NodeList children = node.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                newElement.appendChild(removeNamespacesRecursive(children.item(i), document));
            }
            return newElement;
        } else {
            return document.importNode(node, true);
        }
    }

    /**
     * Создает новый XML-документ, в котором удалены все пространства имен из исходного узла.
     * @param sourceNode Исходный узел, из которого нужно удалить пространства имен.
     * @return Новый XML-документ без пространств имен.
     * @throws ParserConfigurationException если возникла ошибка конфигурации парсера.
     */
    private static Document removeAllNamespaces(Node sourceNode) throws ParserConfigurationException {
        DocumentBuilder db = createDocumentBuilder();
        Document doc = db.newDocument();

        Node newNode = removeNamespacesRecursive(sourceNode, doc);
        doc.appendChild(newNode);
        return doc;
    }

    /**
     * Выполняет канонизацию SOAP Body, имитируя поведение Exchange кода.
     * Каждый дочерний элемент Body обрабатывается как отдельный документ после удаления пространств имен.
     *
     * @param fullSoapXml Полный XML-документ SOAP.
     * @return Канонизированные байты.
     * @throws Exception если возникли ошибки при парсинге или канонизации.
     */
    public static byte[] canonicalizeSoapBody(String fullSoapXml) throws Exception {
        DocumentBuilder db = createDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(fullSoapXml.getBytes(StandardCharsets.UTF_8)));

        XPath xpath = createXPathFactory().newXPath();
        xpath.setNamespaceContext(createSoapNamespaceContext());

        Node bodyNode = (Node) xpath.evaluate("/soap:Envelope/soap:Body", doc, XPathConstants.NODE);
        if (bodyNode == null) {
            throw new Exception("SOAP Body element not found at /soap:Envelope/soap:Body.");
        }

        Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        ByteArrayOutputStream finalStream = new ByteArrayOutputStream();

        NodeList bodyChildren = bodyNode.getChildNodes();
        for (int i = 0; i < bodyChildren.getLength(); i++) {
            Node node = bodyChildren.item(i);

            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Document tempDoc = removeAllNamespaces(node);
                canon.canonicalizeSubtree(tempDoc.getDocumentElement(), finalStream);
            }
        }

        return finalStream.toByteArray();
    }

    /**
     * Загружает публичный ключ из PEM-файла в формате X.509.
     * @param pemFile Файл с публичным ключом в кодировке Base64 между заголовками BEGIN/END PUBLIC KEY.
     * @return Объект PublicKey.
     * @throws IOException если произошла ошибка чтения файла.
     * @throws NoSuchAlgorithmException если алгоритм RSA не найден.
     * @throws InvalidKeySpecException если спецификация ключа недействительна.
     */
    public static PublicKey loadPublicKeyFromPem(File pemFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String key = new String(Files.readAllBytes(pemFile.toPath()));
        key = key.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    /**
     * Верифицирует XML-подпись.
     *
     * @param fullSoapXml Полный XML-документ SOAP.
     * @param signatureBase64 Base64-строка подписи.
     * @param publicKeyFile Файл публичного ключа в формате PEM.
     * @return true, если подпись действительна, иначе false.
     * @throws Exception Если произошла ошибка при канонизации, загрузке ключа или верификации.
     */
    public static boolean verifySignature(String fullSoapXml, String signatureBase64, File publicKeyFile) throws Exception {
        byte[] canonicalBytes = canonicalizeSoapBody(fullSoapXml);
        PublicKey publicKey = loadPublicKeyFromPem(publicKeyFile);

        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initVerify(publicKey);
        signature.update(canonicalBytes);
        return signature.verify(signatureBytes);
    }
}