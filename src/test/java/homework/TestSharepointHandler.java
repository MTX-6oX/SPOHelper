package homework;

import org.homework.Helper;
import org.homework.SharepointHandler;
import org.junit.Test;
import org.junit.jupiter.api.Disabled;

public class TestSharepointHandler {

    @Test
    public void testSPOAuth() {
        //SharepointHandler appInSharepoint = new SharepointHandler("303jyz.sharepoint.com","home_Exports","3c67e304-0560-4398-bde4-68bea44cfef4","uBkQyLT44isor/5G7KUgDwLDGJ2z0q1HldjnMqLQJYs=");
        SharepointHandler appInSharepoint = new SharepointHandler();
        String bearer =appInSharepoint.authenticate();
        System.out.println(bearer);
        String suc = appInSharepoint.uploadFile("C:/data/temp/testfile.csv","Shared%20Documents/uploadTest","testfileSharepoint.csv",bearer);
        System.out.println(suc); //bearer
    }

    @Disabled
    @Test
    public void testAZAuth() {
        SharepointHandler appInAzure = new SharepointHandler("303jyz.sharepoint.com","home_Exports", Helper.config("CLIENT2ID"),Helper.config("CLIENT2SECRET"));
        String bearer =appInAzure.authenticate();
        System.out.println(bearer);
        String suc = appInAzure.uploadFile("C:/data/temp/testfile.csv","Shared%20Documents/uploadTest","testfileAzure.csv",bearer);
        System.out.println(suc); //bearer

    }
}
