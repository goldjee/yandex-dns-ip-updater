import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.*;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Created by Ins on 24.03.2018.
 */
public class DNSUpdater {

    static String configFile = "yandex-dns-ip-updater.conf";
    static String logFile = "log.log";
    static final String dnsURL = "https://pddimp.yandex.ru/api2/admin/dns/edit";
    static final String ipWebhost = "http://wgetip.com/";

    static String token = null;
    static String domain = null;
    static String domainID = null;
    static Map<String, String> subdomains = new HashMap<>();
    static int ttl = -1;
    static String ip = null;

    public static void main(String[] args) {
        System.out.println("Service started");

        File jarFile = null;
        try {
            jarFile = new File(DNSUpdater.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath());
            configFile = jarFile.getParent() + File.separator + configFile;
            logFile = jarFile.getParent() + File.separator + logFile;
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        while (true) {
            try {
                readConfig();
                getIP();
                writeLog("IP address: " + ip);

                List<Map<String, String>> requests = new ArrayList<>();
                requests.add(formParameters(domainID));

                Iterator iterator = subdomains.entrySet().iterator();
                while (iterator.hasNext()) {
                    Map.Entry pair = (Map.Entry) iterator.next();
                    requests.add(formParameters((String) pair.getKey(), (String) pair.getValue()));
                }

                sendRequest(requests.get(1));

                for (Map<String, String> request : requests) {
                    boolean result = sendRequest(request);

                    String log = request.get("domain") + ": ";
                    if (request.containsKey("subdomain"))
                        log += request.get("subdomain") + ": ";
                    if (result)
                        log += "OK";
                    else
                        log += "Error";

                    System.out.println(log);
                    writeLog(log);
                }

            } catch (Exception e) {
                e.printStackTrace();
                try {
                    writeLog("Failed to update DNS records");
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            }

            try {
                Thread.sleep(1000 * 60 * 5);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private static void readConfig() throws Exception {
        Path path = Paths.get(configFile);
        String assigner = "=";

        BufferedReader reader = Files.newBufferedReader(path, Charset.forName("UTF-8"));

        String line = null;
        while ((line = reader.readLine()) != null) {
            if (!(line.length() == 0) && !(line.startsWith("#"))) {
                line = line.replace(" ", "");

                if (line.startsWith("token" + assigner)) {
                    token = line.replace("token" + assigner, "");
                    continue;
                }

                if (line.startsWith("ttl" + assigner)) {
                    line = line.replace("ttl" + assigner, "");
                    ttl = Integer.parseInt(line);
                    continue;
                }

                if (line.startsWith("domain" + assigner)) {
                    if (!line.contains(":"))
                        throw new Exception("Check domain specification in conf file.");
                    else {
                        line = line.replace("domain" + assigner, "");
                        int index = line.indexOf(':');
                        domain = line.substring(0, index);
                        domainID = line.substring(index).replace(":", "");
                    }
                    continue;
                }

                if (line.startsWith("subdomain" + assigner)) {
                    if (!line.contains(":"))
                        throw new Exception("Check subdomain specification in conf file.");
                    else {
                        line = line.replace("subdomain" + assigner, "");
                        int index = line.indexOf(':');
                        String key = line.substring(0, index);
                        String value = line.substring(index).replace(":", "");
                        subdomains.put(key, value);
                    }
                    continue;
                }
            }
        }

        if (token == null)
            throw new Exception("No token specified in conf file.");
        else System.out.println("Yandex.DNS token: " + token);

        if (ttl == -1)
            throw new Exception("No ttl specified in conf file.");
        else System.out.println("TTL: " + ttl);

        if (domain == null)
            throw new Exception("Domain is not present in conf file.");
        else System.out.println("Domain: " + domain + "\tID: " + domainID);

        if (subdomains.isEmpty())
            throw new Exception("No subdomains specified in conf file.");
        else {
            Iterator iterator = subdomains.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry pair = (Map.Entry) iterator.next();
                System.out.println("Subdomain: " + pair.getKey() + "\t ID: " + pair.getValue());
            }
        }
    }

    private static void getIP() throws Exception {
        String line;
        String content = "";

        URL url = new URL(ipWebhost);
        InputStream is = url.openStream();
        BufferedReader br = new BufferedReader(new InputStreamReader(is));

        while ((line = br.readLine()) != null) {
            content += line;
        }

        if (is != null) is.close();

        if (content.length() == 0)
            throw new Exception("Failed to get your IP address. Check if " + ipWebhost + " is accessible.");

        ip = content;
    }

    private static Map<String, String> formParameters(String id) {
        Map<String, String> params = new HashMap<>();
        params.put("domain", domain);
        params.put("record_id", id);
        params.put("content", ip);
        params.put("ttl", String.valueOf(ttl));

        return params;
    }

    private static Map<String, String> formParameters(String subdomain, String id) {
        Map<String, String> params = new HashMap<>();
        params.put("domain", domain);
        params.put("record_id", id);
        params.put("content", ip);
        params.put("ttl", String.valueOf(ttl));
        params.put("subdomain", subdomain);

        return params;
    }

    private static boolean sendRequest(Map<String, String> parameters) throws Exception {
        URL url = new URL(dnsURL);
        URLConnection connection = url.openConnection();
        HttpURLConnection http = (HttpURLConnection)connection;
        http.setRequestMethod("POST"); // PUT is another valid option
        http.setDoOutput(true);

        StringJoiner sj = new StringJoiner("&");
        for(Map.Entry<String,String> entry : parameters.entrySet())
            sj.add(URLEncoder.encode(entry.getKey(), "UTF-8") + "="
                    + URLEncoder.encode(entry.getValue(), "UTF-8"));
        byte[] out = sj.toString().getBytes(StandardCharsets.UTF_8);
        int length = out.length;

        http.setFixedLengthStreamingMode(length);
        http.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8; Host=pddimp.yandex.ru; PddToken=" + token);
        http.setRequestProperty("Host", "pddimp.yandex.ru");
        http.setRequestProperty("PddToken", token);

        http.connect();
        try(OutputStream os = http.getOutputStream()) {
            os.write(out);
        }

        //Get Response
        InputStream is = connection.getInputStream();
        BufferedReader rd = new BufferedReader(new InputStreamReader(is));
        StringBuilder response = new StringBuilder(); // or StringBuffer if Java version 5+
        String line;
        while ((line = rd.readLine()) != null) {
            response.append(line);
            response.append('\r');
        }
        rd.close();
//        System.out.println(response.toString());

        JsonParser parser = new JsonParser();
        JsonObject object = parser.parse(response.toString()).getAsJsonObject();
        String result = object.get("success").getAsString();
//        System.out.println(result);

        return result.equals("ok");
    }

    private static void writeLog(String contents) throws Exception {
        if (!Files.exists(Paths.get(logFile))) {
            Files.createFile(Paths.get(logFile));
        }

        contents = "[" + LocalDateTime.now().toString() + "]" + contents + "\r\n";
        Files.write(Paths.get(logFile), contents.getBytes(), StandardOpenOption.APPEND);
    }
}