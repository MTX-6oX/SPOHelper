package org.homework;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;

public class SharepointHandler {

    Gson gson = new Gson();
    //private final Config config;
    private final String configDomain;
    private final String configSite;
    private final String configClient;
    private final String configSecret;

    public SharepointHandler() {
        configDomain = Helper.prop.getProperty("spo.domain") + "." + Helper.prop.getProperty("spo.host");
        configSite = Helper.prop.getProperty("spo.subsite");
        configClient = Helper.config("CLIENTID");
        configSecret = Helper.config("CLIENTSECRET");
    }

    public SharepointHandler(String domain, String site, String client, String secret) {
        configDomain = domain;
        configSite = site;
        configClient = client;
        configSecret = secret;
    }

    public String authenticate() {
        CloseableHttpClient httpClient = HttpClients.createDefault();

        Pair<String, String> bearerRealmAndRessourceId = getBearerRealmAndRessourceId(httpClient);
        String bearerRealm = bearerRealmAndRessourceId.getLeft();
        String ressourceId = bearerRealmAndRessourceId.getRight();

        String bearerToken = getBearerToken(bearerRealm, ressourceId, httpClient);
        return bearerToken;
    }

    public String uploadFile(String localFilePath, String targetFolder, String targetFilename, String bearer) {
        CloseableHttpClient httpClient = HttpClients.createDefault();

        String content = "";
        try {
            content = FileUtils.readFileToString(new File(localFilePath), "utf-8");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        //String input = "https://%s/sites/%s/_api/web/GetFolderByServerRelativeUrl('"+folder+"')/files/add(overwrite=true,url='" + targetFilename + "')";
        String url = String.format("https://%s/sites/%s/_api/web/GetFolderByServerRelativeUrl('%s')/files/add(overwrite=true,url='%s')", configDomain, configSite, targetFolder, targetFilename);
        //jsonString = SPOnline.post(token, domain, input, content, formDigestValue);
        //https://{site_url}/_api/web/GetFolderByServerRelativeUrl('/Folder Name')/Files

        HttpPost postRequest = new HttpPost(url);
        //Authorization: "Bearer " + accessToken
        //Accept: "application/json;odata=verbose"
        postRequest.setHeader("Authorization", "Bearer " + bearer);
        postRequest.setHeader("Accept", "application/json;odata=verbose");
        postRequest.addHeader("content-type", "application/json;odata=verbose");

        StringEntity input = new StringEntity(content, "UTF-8");
        input.setContentType("application/octet-stream");
        postRequest.setEntity(input);

        try {
            HttpResponse response = httpClient.execute(postRequest);

            String bodyJson = IOUtils.toString(response.getEntity().getContent(), Charset.defaultCharset());
            JsonObject body = gson.fromJson(bodyJson, JsonObject.class);


            String erg = "";
            if (!body.has("d")) {
                erg = bodyJson;
            } else {
                //System.out.println(body.getJSONObject("d").getString("ContentTag"));
                erg = body.getAsJsonObject("d").get("ContentTag").getAsString();
            }

            //String bearerToken = body.getString("ContentTag");
            return erg;
        } catch (Exception e) {
            throw new RuntimeException("Post Request fehlgeschlagen", e);
        }
    }

    private String getBearerToken(String bearerRealm, String ressourceId, CloseableHttpClient httpClient) {
        String url = String.format("https://accounts.accesscontrol.windows.net/%s/tokens/OAuth/2", bearerRealm);

        HttpPost postRequest = new HttpPost(url);
        postRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");

        String clientId = String.format("%s@%s", configClient, bearerRealm);
        String resource = String.format("%s/%s@%s", ressourceId, configDomain, bearerRealm);
        List<NameValuePair> params = List.of(
                //new BasicNameValuePair("scope", String.format("https://%s/Sites.ReadWrite.All", configDomain)),
                new BasicNameValuePair("grant_type", "client_credentials"),
                new BasicNameValuePair("client_id", clientId),//clientId),
                new BasicNameValuePair("client_secret", configSecret),
                new BasicNameValuePair("resource", resource));

        try {
            postRequest.setEntity(new UrlEncodedFormEntity(params));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Parameter falsch formatiert", e);
        }

        try {
            HttpResponse response = httpClient.execute(postRequest);

            String bodyJson = IOUtils.toString(response.getEntity().getContent(), Charset.defaultCharset());
            JsonObject body = gson.fromJson(bodyJson, JsonObject.class);
            String bearerToken = body.get("access_token").getAsString();
            return bearerToken;
        } catch (Exception e) {
            throw new RuntimeException("Post Request zum Holen des Bearer Tokens fehlgeschlagen", e);
        }
    }

    private Pair<String, String> getBearerRealmAndRessourceId(CloseableHttpClient httpClient) {
        // domain = mysharepoint.sharepoint.com
        String url = String.format("https://%s/_layouts/15/sharepoint.aspx", configDomain);

        HttpGet getRequest = new HttpGet(url);
        getRequest.setHeader("Authorization", "Bearer");

        try {
            HttpResponse response = httpClient.execute(getRequest);
            Header[] headers = response.getHeaders("www-authenticate");

            String bearerRealm = extractHeaderElement(headers, "Bearer realm");
            String ressourceId = extractHeaderElement(headers, "client_id");
            return Pair.of(bearerRealm, ressourceId);
        } catch (Exception e) {
            throw new RuntimeException("Get Request zum Holen von Bearer realm und client_id fehlgeschlagen", e);
        }
    }

    private String extractHeaderElement(Header[] headers, String elementName) {
        return Arrays.asList(headers).stream().map(header -> header.getElements()).flatMap(elements -> Arrays.asList(elements).stream()).filter(element -> element.getName().equals(elementName)).findFirst().orElseThrow().getValue();
    }
}