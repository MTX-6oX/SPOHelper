package homework;

import com.google.common.net.UrlEscapers;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.homework.SPOnline;
import org.json.JSONObject;
import org.junit.Test;

public class TestUploadFile {
//synapse3989@303jyz.onmicrosoft.com
	private static final String USERNAME="synapse3989@303jyz.onmicrosoft.com";
	private static final String DOMAIN="303jyz";

	@Test
	public void testUpload() {

		System.out.println(SPOnline.uploadWithHelper("303jyz","home_Exports",
				"Shared%20Documents/longIAB","testfile.csv",
				"synapse3989@303jyz.onmicrosoft.com", "C:/data/temp/testfile.csv"));

		System.out.println(SPOnline.uploadWithHelper("303jyz","home_Exports",
				"Shared%20Documents/longIAB","testfile.csv",
				"HenriettaM@303jyz.onmicrosoft.com", "C:/data/temp/testfile.csv"));

		/*try {
			List<String> lines = IOUtils.readLines(new FileReader(System.getProperty("user.home") + File.separator + "password.txt"));
			String password = lines.get(0);
			String domain = DOMAIN;
			Pair<String, String> token = SPOnline.login(USERNAME, password, domain);
			if (token != null) {
				String jsonString = SPOnline.post(token, domain, "sites/home_Exports/_api/contextinfo", null, null);
				System.out.println(SPOnline.prettyFormatJson(jsonString));
				JSONObject json = new JSONObject(jsonString);
				String formDigestValue = json.getJSONObject("d").getJSONObject("GetContextWebInformation").getString("FormDigestValue");
				System.out.println("FormDigestValue=" + formDigestValue);
				//FDV is needed for subsequent POSTs

				//write to file jsonString = SPOnline.post(token, domain, "/_api/web/lists/GetByTitle('doclib1')/rootfolder/files/add(overwrite=true,url='filename.txt')", "fuck", formDigestValue);
				String filepath = "C:/data/temp/testfile.csv";
				String content = FileUtils.readFileToString(new File(filepath), "utf-8");
				//https://303jyz.sharepoint.com/:x:/s/home_Exports/Ec9nE9vrZ4JMtLNzDKPb0fcBGCmQsoKmlRyzPsWX6WnZdQ?e=arcR03
				//jsonString = SPOnline.post(token, domain, "/_api/web/lists/GetByTitle('home_Exports')/rootfolder/files/add(overwrite=true,url='filename.txt')", "fuck", formDigestValue);
				//jsonString = SPOnline.post(token, domain, "/_api/web/getfolderbyserverrelativeurl('" + UrlEscapers.urlFragmentEscaper().escape("/home_Exports") + "')/files/add(overwrite=true,url='" + UrlEscapers.urlFragmentEscaper().escape("testfile.csv") + "')", content, formDigestValue);
				String input = "sites/home_Exports/_api/web/GetFolderByServerRelativeUrl('Shared%20Documents/longIAB')/files/add(overwrite=true,url='" + UrlEscapers.urlFragmentEscaper().escape("testfile.csv") + "')";
				jsonString = SPOnline.post(token, domain, input, content, formDigestValue, true);
				//https://{site_url}/_api/web/GetFolderByServerRelativeUrl('/Folder Name')/Files
				if (jsonString != null) {
					System.out.println(SPOnline.prettyFormatJson(jsonString));
				}
			} else {
				System.err.println("Login failed");
			}
		} catch (FileNotFoundException ex) {
			Logger.getLogger(TestUploadFile.class.getName()).log(Level.SEVERE, null, ex);
		} catch (IOException ex) {
			Logger.getLogger(TestUploadFile.class.getName()).log(Level.SEVERE, null, ex);
		}*/
	}
}
