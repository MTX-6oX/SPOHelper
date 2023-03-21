package org.homework;

import java.io.*;
import java.net.CookieHandler;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.FileEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class SPOnline {

	final static Logger logger = Logger.getLogger(SPOnline.class);
	public static String sharepointHost = Helper.prop.getProperty("spo.host"); //"sharepoint.com"; //"onmicrosoft.com";

	public static String stsUrl = Helper.prop.getProperty("spo.stsurl"); //"https://login.microsoftonline.com/extSTS.srf";

	static {
		System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http", "warn");
	}

	public static void main(String args[]) {
		if (args.length == 3) {
			Pair<String, String> token = SPOnline.login(args[0], args[1], args[2]);
			if (token != null) {
				System.out.println(token.getLeft());
				System.out.println(token.getRight());
			}
		} else {
			try {
				Properties prop = new Properties();
				prop.load(SPOnline.class.getClassLoader().getResourceAsStream("messages_en_US.properties"));
				System.out.println("version " + prop.getProperty("version") + ", build date " + prop.getProperty("build.date"));
			} catch (IOException ex) {
				java.util.logging.Logger.getLogger(SPOnline.class.getName()).log(Level.SEVERE, null, ex);
			}
		}
	}

	public static String uploadWithHelper(String inDomain, String site, String folder, String targetFilename, String user, String localFilePath) {
		String output="x";
		try {
			List<String> lines = IOUtils.readLines(new FileReader(System.getProperty("user.home") + File.separator + "password.txt"));
			String password = lines.get(0);
			String USERNAME = user;
			String domain = inDomain;
			Pair<String, String> token = SPOnline.login(USERNAME, password, domain);
			if (token != null) {
				String jsonString = SPOnline.post(token, domain, "sites/"+site+"/_api/contextinfo", null, null);
				System.out.println(SPOnline.prettyFormatJson(jsonString));
				JSONObject json = new JSONObject(jsonString);
				String formDigestValue = json.getJSONObject("d").getJSONObject("GetContextWebInformation").getString("FormDigestValue");
				System.out.println("FormDigestValue=" + formDigestValue);
				//FDV is needed for subsequent POSTs

				String filepath = localFilePath;
				String content = FileUtils.readFileToString(new File(filepath), "utf-8");
				String input = "sites/"+site+"/_api/web/GetFolderByServerRelativeUrl('"+folder+"')/files/add(overwrite=true,url='" + targetFilename + "')";
				jsonString = SPOnline.post(token, domain, input, content, formDigestValue);
				//https://{site_url}/_api/web/GetFolderByServerRelativeUrl('/Folder Name')/Files
				if (jsonString != null) {
					System.out.println(SPOnline.prettyFormatJson(jsonString));
					JSONObject json2 = new JSONObject(jsonString);
					if(!json2.has("d")) {
						output=jsonString;
					} else {
						System.out.println(json2.getJSONObject("d").getString("ContentTag"));
						output="success";
					}

				}
			} else {
				System.err.println("Login failed");
				output="Login failed";
			}
		} catch (IOException ex) {
			java.util.logging.Logger.getLogger(SPOnline.class.getName()).log(Level.SEVERE, null, ex);
			output= String.valueOf(ex);
		}
		return output;
	}

	public static Pair<String, String> login(String username, String password, String domain) {
		username = StringEscapeUtils.escapeXml11(username);
		password = StringEscapeUtils.escapeXml11(password);
		Pair<String, String> result;
		String token;
		try {
			token = requestToken(domain, username, password);
			if (token == null) {
				return null;
			}
			result = submitToken(domain, token);
			return result;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private static String requestToken(String domain, String username, String password) throws XPathExpressionException, SAXException, ParserConfigurationException, IOException {
		String saml = generateSAML(domain, username, password);
		System.out.println(saml);
		System.out.println("---");
		String sts = stsUrl;
		URL u = new URL(sts);
		URLConnection uc = u.openConnection();
		HttpURLConnection connection = (HttpURLConnection) uc;

		connection.setDoOutput(true);
		connection.setDoInput(true);
		connection.setRequestMethod("POST");
		connection.addRequestProperty("Content-Type", "text/xml; charset=utf-8");
		OutputStream out = connection.getOutputStream();
		Writer writer = new OutputStreamWriter(out);
		writer.write(saml);

		writer.flush();
		writer.close();

		InputStream in = connection.getInputStream();
		int c;
		StringBuilder sb = new StringBuilder("");
		while ((c = in.read()) != -1) {
			sb.append((char) (c));
		}
		in.close();
		String result = sb.toString();
		String token = extractToken(result);
		if (token == null || token.equals("")) {
			logger.error("Login failed : " + prettyFormatXml(result, 4));
			return null;
		}
		return token;
	}

	private static String generateSAML(String domain, String username, String password) {
		String reqXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				+ "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">\n"
				+ "   <s:Header>\n"
				+ "      <a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>\n"
				+ "      <a:ReplyTo>\n"
				+ "         <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>\n"
				+ "      </a:ReplyTo>\n"
				+ "      <a:To s:mustUnderstand=\"1\">https://login.microsoftonline.com/extSTS.srf</a:To>\n"
				+ "      <o:Security xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" s:mustUnderstand=\"1\">\n"
				+ "         <o:UsernameToken>\n"
				+ "            <o:Username>[[username]]</o:Username>\n"
				+ "            <o:Password>[[password]]</o:Password>\n"
				+ "         </o:UsernameToken>\n"
				+ "      </o:Security>\n"
				+ "   </s:Header>\n"
				+ "   <s:Body>\n"
				+ "      <t:RequestSecurityToken xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">\n"
				+ "         <wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">\n"
				+ "            <a:EndpointReference>\n"
				+ "               <a:Address>[[endpoint]]</a:Address>\n"
				+ "            </a:EndpointReference>\n"
				+ "         </wsp:AppliesTo>\n"
				+ "         <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>\n"
				+ "         <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>\n"
				+ "         <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>\n"
				+ "      </t:RequestSecurityToken>\n"
				+ "   </s:Body>\n"
				+ "</s:Envelope>";
		String saml = reqXML.replace("[[username]]", username);
		saml = saml.replace("[[password]]", password);
		saml = saml.replace("[[endpoint]]", String.format("https://%s." + sharepointHost + "/_forms/default.aspx?wa=wsignin1.0", domain));
		return saml;
	}

	private static String extractToken(String result) throws SAXException, IOException, ParserConfigurationException, XPathExpressionException {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder db = dbf.newDocumentBuilder();
		Document document = db.parse(new InputSource(new StringReader(result)));
		XPathFactory xpf = XPathFactory.newInstance();
		XPath xp = xpf.newXPath();
		String token = xp.evaluate("//BinarySecurityToken/text()", document.getDocumentElement());
		return token;
	}

	private static Pair<String, String> submitToken(String domain, String token) throws IOException {
		String loginContextPath = "/_forms/default.aspx?wa=wsignin1.0";
		String url = String.format("https://%s." + sharepointHost + "%s", domain, loginContextPath);
		CookieHandler.setDefault(null);
		URL u = new URL(url);
		URLConnection uc = u.openConnection();
		HttpURLConnection connection = (HttpURLConnection) uc;
		connection.setDoOutput(true);
		connection.setDoInput(true);
		connection.setRequestMethod("POST");
		connection.addRequestProperty("Accept", "application/x-www-form-urlencoded");
//		connection.addRequestProperty("Content-Type", "text/xml; charset=utf-8");
		connection.setInstanceFollowRedirects(false);
		OutputStream out = connection.getOutputStream();
		Writer writer = new OutputStreamWriter(out);
		writer.write(token);
		writer.flush();
		out.flush();
		writer.close();
		out.close();

		String rtFa = null;
		String fedAuth = null;
		Map<String, List<String>> headerFields = connection.getHeaderFields();
		List<String> cookiesHeader = headerFields.get("Set-Cookie");
		if (cookiesHeader != null) {
			for (String cookie : cookiesHeader) {
				if (cookie.startsWith("rtFa=")) {
					rtFa = "rtFa=" + HttpCookie.parse(cookie).get(0).getValue();
				} else if (cookie.startsWith("FedAuth=")) {
					fedAuth = "FedAuth=" + HttpCookie.parse(cookie).get(0).getValue();
				} else {
					//logger.info("waste=" + HttpCookie.parse(cookie).get(0).getValue());
				}
			}
		}
		Pair<String, String> result = ImmutablePair.of(rtFa, fedAuth);
		return result;
	}

	public static String contextinfo(Pair<String, String> token, String domain) {
		CloseableHttpClient httpClient = HttpClients.createDefault();
		try {
			HttpPost getRequest = new HttpPost("https://" + domain + "." + sharepointHost + "/_api/contextinfo");
			getRequest.addHeader("Cookie", token.getLeft() + ";" + token.getRight());
			getRequest.addHeader("accept", "application/json;odata=verbose");
			HttpResponse response = httpClient.execute(getRequest);
			if (response.getStatusLine().getStatusCode() == 200) {
				return IOUtils.toString(response.getEntity().getContent(), "utf-8");
			} else {
				throw new RuntimeException("Failed : HTTP error code : " + response.getStatusLine().getStatusCode());
			}
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				httpClient.close();
			} catch (IOException ex) {
				Logger.getLogger(SPOnline.class).error(ex);
			}
		}
		return null;
	}

	public static String get(Pair<String, String> token, String url) {
		CloseableHttpClient httpClient = HttpClients.createDefault();
		try {
			HttpGet getRequest = new HttpGet(url);
			getRequest.addHeader("Cookie", token.getLeft() + ";" + token.getRight());
			getRequest.addHeader("accept", "application/json;odata=verbose");
			HttpResponse response = httpClient.execute(getRequest);
			if (response.getStatusLine().getStatusCode() == 200) {
				return IOUtils.toString(response.getEntity().getContent(), "utf-8");
			} else {
				System.err.println("Failed : HTTP error code : " + response.getStatusLine().getStatusCode() + ", " + url);
				return null;
			}
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				httpClient.close();
			} catch (IOException ex) {
				Logger.getLogger(SPOnline.class).error(ex);
			}
		}
		return null;
	}

	public static String get(Pair<String, String> token, String domain, String path) {
		return get(token, "https://" + domain + "." + sharepointHost + "/" + path);
	}

	public static byte[] download(Pair<String, String> token, String url) {
		CloseableHttpClient httpClient = HttpClients.createDefault();
		try {
			HttpGet getRequest = new HttpGet(url);
			getRequest.addHeader("Cookie", token.getLeft() + ";" + token.getRight());
			getRequest.addHeader("accept", "application/octet-stream");
			HttpResponse response = httpClient.execute(getRequest);
			if (response.getStatusLine().getStatusCode() == 200) {
				InputStream is = response.getEntity().getContent();
				byte[] bytes = IOUtils.toByteArray(is);
				return bytes;
			} else {
				System.err.println("Failed : HTTP error code : " + response.getStatusLine().getStatusCode() + ", " + url);
				return null;
			}
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				httpClient.close();
			} catch (IOException ex) {
				Logger.getLogger(SPOnline.class).error(ex);
			}
		}
		return null;
	}

	public static byte[] download(Pair<String, String> token, String domain, String path) {
		return download(token, "https://" + domain + "." + sharepointHost + "/" + path);
	}

	public static JSONObject getJSON(Pair<String, String> token, String domain, String path) {
		return new JSONObject(get(token, domain, path));
	}

	public static String post(Pair<String, String> token, String domain, String path, String data, String formDigestValue) {
		return post(token, domain, path, data, formDigestValue, false);
	}

	public static String post(Pair<String, String> token, String domain, String path, String data, String formDigestValue, boolean isUpload) {
		return post(token, domain, path, data, formDigestValue, false, isUpload);
	}

	public static JSONObject postJSON(Pair<String, String> token, String domain, String path, String data, String formDigestValue) {
		return new JSONObject(post(token, domain, path, data, formDigestValue, false));
	}

	public static String post(Pair<String, String> token, String domain, String path, String data, String formDigestValue, boolean isXHttpMerge, boolean isUpload) {
		CloseableHttpClient httpClient = HttpClients.createDefault();
		try {
			HttpPost postRequest = new HttpPost("https://" + domain + "." + sharepointHost + "/" + path);
			postRequest.addHeader("Cookie", token.getLeft() + ";" + token.getRight());
			postRequest.addHeader("accept", "application/json;odata=verbose");
			postRequest.addHeader("content-type", "application/json;odata=verbose");
			postRequest.addHeader("X-RequestDigest", formDigestValue);
			postRequest.addHeader("IF-MATCH", "*");
			if (isXHttpMerge) {
				postRequest.addHeader("X-HTTP-Method", "MERGE");
			}

			if (isUpload) {
				StringEntity input = new StringEntity(data, "UTF-8");
				input.setContentType("application/octet-stream");
				postRequest.setEntity(input);
			} else if (data != null) {
				StringEntity input = new StringEntity(data, "UTF-8");
				input.setContentType("application/json");
				postRequest.setEntity(input);
			}
			System.out.println("post:");
			for(Header x : postRequest.getAllHeaders()) {
				System.out.print(x.getName());
				System.out.println(x.getValue());
			}

			System.out.println(postRequest);
			System.out.println("---");
			HttpResponse response = httpClient.execute(postRequest);
			if (response.getStatusLine().getStatusCode() != 200 && response.getStatusLine().getStatusCode() != 201 && response.getStatusLine().getStatusCode() != 204) {
				logger.error("Failed : HTTP error code : " + response.getStatusLine().getStatusCode() + ", " + path);
			}
			if (response.getEntity() == null || response.getEntity().getContent() == null) {
				return null;
			} else {
				return IOUtils.toString(response.getEntity().getContent(), "utf-8");
			}
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				httpClient.close();
			} catch (IOException ex) {
				Logger.getLogger(SPOnline.class).error(ex);
			}
		}
		return null;
	}

	public static String post(Pair<String, String> token, String domain, String path, byte bytes[], String formDigestValue, boolean isXHttpMerge, boolean isUpload) {
		CloseableHttpClient httpClient = HttpClients.createDefault();
		try {
			HttpPost postRequest = new HttpPost("https://" + domain + "." + sharepointHost + "/" + path);
			postRequest.addHeader("Cookie", token.getLeft() + ";" + token.getRight());
			postRequest.addHeader("accept", "application/json;odata=verbose");
			postRequest.addHeader("content-type", "application/json;odata=verbose");
			postRequest.addHeader("X-RequestDigest", formDigestValue);
			postRequest.addHeader("IF-MATCH", "*");
			if (isXHttpMerge) {
				postRequest.addHeader("X-HTTP-Method", "MERGE");
			}

			if (isUpload) {
				ByteArrayEntity input = new ByteArrayEntity(bytes);
				input.setContentType("application/octet-stream");
				postRequest.setEntity(input);
			} else if (bytes != null) {
				ByteArrayEntity input = new ByteArrayEntity(bytes);
				input.setContentType("application/json");
				postRequest.setEntity(input);
			}

			HttpResponse response = httpClient.execute(postRequest);
			if (response.getStatusLine().getStatusCode() != 200 && response.getStatusLine().getStatusCode() != 204) {
				logger.error("Failed : HTTP error code : " + response.getStatusLine().getStatusCode() + ", " + path);
			}
			if (response.getEntity() == null || response.getEntity().getContent() == null) {
				return null;
			} else {
				return IOUtils.toString(response.getEntity().getContent(), "utf-8");
			}
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				httpClient.close();
			} catch (IOException ex) {
				Logger.getLogger(SPOnline.class).error(ex);
			}
		}
		return null;
	}

	public static String post(Pair<String, String> token, String domain, String path, File file, String formDigestValue, boolean isXHttpMerge) {
		CloseableHttpClient httpClient = HttpClients.createDefault();
		try {
			HttpPost postRequest = new HttpPost("https://" + domain + "." + sharepointHost + "/" + path);
			postRequest.addHeader("Cookie", token.getLeft() + ";" + token.getRight());
			postRequest.addHeader("accept", "application/json;odata=verbose");
			postRequest.addHeader("content-type", "application/json;odata=verbose");
			postRequest.addHeader("X-RequestDigest", formDigestValue);
			postRequest.addHeader("IF-MATCH", "*");
			if (isXHttpMerge) {
				postRequest.addHeader("X-HTTP-Method", "MERGE");
			}

			FileEntity reqEntity = new FileEntity(file, ContentType.APPLICATION_OCTET_STREAM);
			postRequest.setEntity(reqEntity);

			HttpResponse response = httpClient.execute(postRequest);
			if (response.getStatusLine().getStatusCode() != 200 && response.getStatusLine().getStatusCode() != 204) {
				logger.error("Failed : HTTP error code : " + response.getStatusLine().getStatusCode() + ", " + path);
			}
			if (response.getEntity() == null || response.getEntity().getContent() == null) {
				return null;
			} else {
				return IOUtils.toString(response.getEntity().getContent(), "utf-8");
			}
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				httpClient.close();
			} catch (IOException ex) {
				Logger.getLogger(SPOnline.class).error(ex);
			}
		}
		return null;
	}

	public static String delete(Pair<String, String> token, String domain, String path, String formDigestValue) {
		CloseableHttpClient httpClient = HttpClients.createDefault();
		try {
			HttpDelete deleteRequest = new HttpDelete("https://" + domain + "." + sharepointHost + "/" + path);
			deleteRequest.addHeader("Cookie", token.getLeft() + ";" + token.getRight());
			deleteRequest.addHeader("accept", "application/json;odata=verbose");
			deleteRequest.addHeader("content-type", "application/json;odata=verbose");
			deleteRequest.addHeader("X-RequestDigest", formDigestValue);
			deleteRequest.addHeader("IF-MATCH", "*");
			HttpResponse response = httpClient.execute(deleteRequest);
			if (response.getStatusLine().getStatusCode() != 200 && response.getStatusLine().getStatusCode() != 204) {
				logger.error("Failed : HTTP error code : " + response.getStatusLine().getStatusCode());
			}
			if (response.getEntity() == null || response.getEntity().getContent() == null) {
				return null;
			} else {
				return IOUtils.toString(response.getEntity().getContent(), "utf-8");
			}
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				httpClient.close();
			} catch (IOException ex) {
				Logger.getLogger(SPOnline.class).error(ex);
			}
		}
		return null;
	}

	public static String prettyFormatXml(String xml, int indent) {
		try {
			Source xmlInput = new StreamSource(new StringReader(xml));
			StringWriter stringWriter = new StringWriter();
			StreamResult xmlOutput = new StreamResult(stringWriter);
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			transformerFactory.setAttribute("indent-number", indent);
			Transformer transformer = transformerFactory.newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.transform(xmlInput, xmlOutput);
			return xmlOutput.getWriter().toString();
		} catch (Exception e) {
			throw new RuntimeException(e); // simple exception handling, please review it
		}
	}

	public static String prettyFormatJson(String json) {
		JsonParser parser = new JsonParser();
		Gson gson = new GsonBuilder().setPrettyPrinting().create();

		JsonElement el = parser.parse(json);
		String jsonString = gson.toJson(el);
		return jsonString;
	}

	public static String escapeSharePointUrl(String path) {
		return path.replaceAll(" ", "%20");
	}
}
