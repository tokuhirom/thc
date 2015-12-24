package me.geso.thc;

import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import javax.net.SocketFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocketFactory;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// TODO https support
// TODO HTTP/2 support

enum HttpResponseParserCode {
    OK,
    PARTIAL
}

@ToString
class HttpResponse {
    private static final Pattern statusPattern = Pattern.compile("\\A(HTTP/1\\.[01]+) ([0-9]+) (\\S+?)\\r?\\n");
    private static final Pattern headerPattern = Pattern.compile("\\A([a-zA-Z0-9_-]+)[ ]*:[ ]*([^\\r\\n]+?)\\r?\\n", Pattern.UNIX_LINES);

    @Getter
    private String protocol;
    @Getter
    private int status;
    @Getter
    private String message;
    @Getter
    private HttpHeaders headers;

    public HttpResponse() {
        this.headers = new HttpHeaders();
    }

    public static HttpResponseParserResult parse(String buf) {
        buf = "" + buf;
        Matcher matcher = statusPattern.matcher(buf);
        HttpResponse httpResponse = new HttpResponse();

        if (matcher.find()) {
            buf = buf.substring(matcher.group(0).length());

            httpResponse.protocol = matcher.group(1);
            httpResponse.status = Integer.parseInt(matcher.group(2));
            httpResponse.message = matcher.group(3);
        } else {
            return HttpResponseParserResult.partial();
        }

        while (true) {
            Matcher matcher2 = headerPattern.matcher(buf);
            if (matcher2.find()) {
                String key = matcher2.group(1);
                String value = matcher2.group(2);
                httpResponse.headers.add(key, value);
                buf = buf.substring(matcher2.group(0).length());
            } else {
                if (buf.startsWith("\r\n") || buf.startsWith("\n")) {
                    return HttpResponseParserResult.ok(httpResponse, buf);
                }
                break;
            }
        }
        return HttpResponseParserResult.partial();
    }

    static class HttpResponseParserResult {
        @Getter
        private HttpResponseParserCode code;
        @Getter
        private HttpResponse response;
        private byte[] remains;

        public HttpResponseParserResult(HttpResponseParserCode code) {
            this.code = code;
        }

        public static HttpResponseParserResult partial() {
            return new HttpResponseParserResult(HttpResponseParserCode.PARTIAL);
        }

        public static HttpResponseParserResult ok(HttpResponse response, String remains) {
            HttpResponseParserResult httpResponseParserResult = new HttpResponseParserResult(HttpResponseParserCode.OK);
            httpResponseParserResult.response = response;
            httpResponseParserResult.remains = remains.getBytes(StandardCharsets.US_ASCII);
            return httpResponseParserResult;
        }

        public ByteBuffer getRemains() {
            return ByteBuffer.wrap(this.remains);
        }
    }
}

interface HttpHandler {
    void onHeader(HttpResponse response);

    void onBody(ByteBuffer byteBuffer);
}

@ToString
class HttpHeaders {
    private Map<String, List<String>> headers;

    public HttpHeaders() {
        headers = new LinkedHashMap<>();
    }

    public HttpHeaders add(String name, String value) {
        name = name.toLowerCase();

        if (!headers.containsKey(name)) {
            headers.put(name, new ArrayList<>());
        }
        headers.get(name).add(value);
        return this;
    }

    public Set<String> keySet() {
        return headers.keySet();
    }

    public List<String> get(String key) {
        return headers.get(key);
    }
}

@Slf4j
class StringHttpRequest extends HttpRequest {
    private final ByteBuffer buffer;
    private final byte[] bytes;
    private long wroteBytes = 0;

    public StringHttpRequest(String method, URI uri, String content) {
        super(method, uri);
        getHeaders().add("Content-Length", String.valueOf(content.length()));
        this.bytes = content.getBytes(StandardCharsets.UTF_8);
        this.buffer = ByteBuffer.wrap(this.bytes);
    }

    @Override
    public boolean writeEntity(SocketChannel sch) throws IOException {
        int wrote = sch.write(buffer);
        wroteBytes += wrote;
        log.info("wrote " + wrote);
        return this.bytes.length != wroteBytes;
    }
}

class HttpRequest {
    private URI uri;
    private String method;
    private HttpHeaders headers;

    public HttpRequest(String method, URI uri) {
        this.uri = uri;
        this.method = method;
        this.headers = new HttpHeaders();
        // should we add port number to host header?
        headers.add("Host", uri.getHost());
    }

    public static HttpRequest get(URI uri) {
        return new HttpRequest("GET", uri);
    }

    private void setMethod(String method) {
        this.method = method;
    }

    public URI getUri() {
        return uri;
    }

    public void setUri(URI uri) {
        this.uri = uri;
    }

    public String getHost() {
        return uri.getHost();
    }

    public int getPort() {
        int port = uri.getPort();
        if (port == -1) {
            switch (uri.getScheme()) {
                case "http":
                    return 80;
                case "https":
                    return 443;
                default:
                    throw new IllegalStateException("Invalid scheme: " + uri);
            }
        } else {
            return port;
        }
    }

    public String getMethod() {
        return method;
    }

    public String getHeaderPartAsString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(method).append(" ").append(uri.getRawPath()).append(" HTTP/1.0\r\n");
        for (String key : headers.keySet()) {
            for (String val : headers.get(key)) {
                stringBuilder.append(key + " : " + val + "\r\n");
            }
        }
        stringBuilder.append("\r\n");
        return stringBuilder.toString();
    }

    public HttpHeaders getHeaders() {
        return headers;
    }

    public boolean writeEntity(SocketChannel sch) throws IOException {
        return false; // finished.
    }

    public boolean isSsl() {
        return "https".equals(uri.getScheme());
    }
}

enum HttpStateType {
    NOT_CONNECTED,
    CONNECTED,
    HEADER_SENT,
    ENTITY_SENT,
    HEADER_RECEIVED
}

class HttpState {
    ByteBuffer buf;
    HttpHandler httpHandler;
    HttpStateType state;
    HttpRequest httpRequest;
    long read;

    public HttpState(HttpRequest httpRequest, HttpHandler httpHandler) {
        this.state = HttpStateType.NOT_CONNECTED;
        this.httpRequest = httpRequest;
        this.httpHandler = httpHandler;
        this.buf = ByteBuffer.allocate(1024);
        this.read = 0;
    }
}

@Slf4j
class HttpClient implements Closeable {
    private Set<SocketChannel> channels;
    private SocketFactory socketFactory = SSLSocketFactory.getDefault();

    private final Selector selector;

    public HttpClient() throws IOException {
        selector = Selector.open();
        this.channels = new HashSet<>();
    }

    public void get(URI uri, HttpHandler httpHandler) throws IOException {
        log.info("get: " + uri);
        this.request(HttpRequest.get(uri), httpHandler);
    }

    public void request(HttpRequest request, HttpHandler handler) throws IOException {
        // TODO keep-alive support
        request.getHeaders().add("Connection", "close");

        InetSocketAddress inetSocketAddress = new InetSocketAddress(request.getHost(), request.getPort());
        if (request.isSsl()) {
            Socket socket = socketFactory.createSocket(request.getHost(), request.getPort());
        } else {
            SocketChannel socketChannel = request.isSsl()
                    ? socketFactory.createSocket(request.getHost(), request.getPort()).getChannel()
                    : SocketChannel.open();
            socketChannel.configureBlocking(false);
            socketChannel.connect(inetSocketAddress);

            SelectionKey selectionKey = socketChannel.register(selector, SelectionKey.OP_CONNECT);
            selectionKey.attach(new HttpState(request, handler));
            this.channels.add(socketChannel);
        }
    }

    public void waitAll() {
        while (!this.channels.isEmpty()) {
            try {
                selector.select();
            } catch (IOException e) {
                log.warn("IOException: {}", e.getMessage());
            }
            Set keys = selector.selectedKeys();
            if (!keys.isEmpty()) {
                Iterator iterator = keys.iterator();
                while (iterator.hasNext()) {
                    SelectionKey key = (SelectionKey) iterator.next();
                    iterator.remove();

                    HttpState state = (HttpState) key.attachment();

                    if (key.isConnectable()) {
                        log.info("connecting connection!");
                        SocketChannel sch = (SocketChannel) key.channel();
                        try {
                            sch.finishConnect();
                            state.state = HttpStateType.CONNECTED;
                            log.info(String.valueOf(sch.isBlocking()));
                            log.info(String.valueOf(sch.isConnected()));
                            key.interestOps(SelectionKey.OP_WRITE);
                        } catch (IOException e) {
                            try {
                                sch.close();
                            } catch (IOException e1) {
                                log.info("Can't close connection: " + e1.getMessage());
                            }
                        }
                    } else if (key.isWritable()) {
                        log.info("writing");
                        SocketChannel sch = (SocketChannel) key.channel();
                        try {
                            if (state.state == HttpStateType.CONNECTED) {
                                ByteBuffer src = ByteBuffer.wrap(
                                        state.httpRequest.getHeaderPartAsString().getBytes(StandardCharsets.US_ASCII));
                                sch.write(src);
                                state.state = HttpStateType.HEADER_SENT;
                            } else {
                                // TODO send entity
                                if (!state.httpRequest.writeEntity(sch)) {
                                    state.state = HttpStateType.ENTITY_SENT;
                                    key.interestOps(SelectionKey.OP_READ);
                                }
                            }
                        } catch (IOException e) {
                            try {
                                sch.close();
                            } catch (IOException e1) {
                                log.info("Can't close connection: " + e1.getMessage());
                            }
                        }
                    } else if (key.isReadable()) {
                        log.info("reading");
                        SocketChannel sch = (SocketChannel) key.channel();
                        try {
                            ByteBuffer buf = state.buf;
                            int read = sch.read(buf);
                            if (read <= 0) {
                                sch.close();
                                this.channels.remove(sch);
                                continue;
                            }
                            log.info("got " + read);
                            buf.flip();
                            if (state.state == HttpStateType.ENTITY_SENT) {
                                String got = new String(buf.array(), buf.arrayOffset() + buf.position(),
                                        buf.remaining(), StandardCharsets.UTF_8);
                                HttpResponse.HttpResponseParserResult result = HttpResponse.parse(got);
                                switch (result.getCode()) {
                                    case OK:
                                        log.info("PARSED");
                                        state.state = HttpStateType.HEADER_RECEIVED;
                                        state.httpHandler.onHeader(result.getResponse());
                                        state.read += result.getRemains().remaining();
                                        state.httpHandler.onBody(result.getRemains());
                                        break;
                                    case PARTIAL:
                                        log.info("PARTIAL");
                                        break;
                                }
                            } else {
                                state.read += buf.remaining();
                                state.httpHandler.onBody(buf);
                            }
                        } catch (IOException e) {
                            log.info("Can't read from connection: " + e.getMessage());
                        }
                    }
                    if (!key.isValid()) {
                        try {
                            key.channel().close();
                        } catch (IOException e) {
                            log.info("Can't close connection: " + e.getMessage());
                        }
                    }
                }
            }
        }
    }

    @Override
    public void close() throws IOException {
        selector.close();
    }

    public void post(URI uri, String content, HttpHandler httpHandler) throws IOException {
        StringHttpRequest httpRequest = new StringHttpRequest("POST", uri, content);
        this.request(httpRequest, httpHandler);
    }
}

public class Main {

    public static void main(String[] args) throws IOException {
        try (HttpClient httpClient = new HttpClient()) {
            httpClient.post(URI.create("https://twitter.com/"), "hoge", new HttpHandler() {
                @Override
                public void onHeader(HttpResponse response) {
                    System.out.println(response);
                }

                @Override
                public void onBody(ByteBuffer buf) {
                    String got = new String(buf.array(), buf.arrayOffset() + buf.position(),
                            buf.remaining(), StandardCharsets.UTF_8);

                    System.out.println("GOT: " + got);
                }
            });

//            for (int i = 0; i < 10; ++i) {
//                httpClient.get(URI.create("http://64p.org/"), new HttpHandler() {
//                    @Override
//                    public void onHeader(HttpResponse response) {
//                        System.out.println(response);
//                    }
//
//                    @Override
//                    public void onBody(ByteBuffer buf) {
//                        String got = new String(buf.array(), buf.arrayOffset() + buf.position(),
//                                buf.remaining(), StandardCharsets.UTF_8);
//
//                        System.out.println("GOT: " + got);
//                    }
//                });
//            }
            httpClient.waitAll();
        }
    }
}

