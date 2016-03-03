package com.dogjaw.services.authentication.b2c;

import com.dogjaw.services.authentication.AzureB2CApplication;
import com.dogjaw.services.authentication.services.RsaKeyCachingService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.IOException;

/**
 * Created by Keith Hoopes on 2/25/2016. *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = AzureB2CApplication.class)
public class RsaKeyClientTest {

    @Autowired
    RsaKeyClient rsaKeyClient;

    @Autowired
    MetaDataClient metaDataClient;

    @Autowired
    RsaKeyCachingService keyCachingService;

    @Test
    public void load() {

        assert rsaKeyClient != null;
        assert metaDataClient != null;
        assert keyCachingService != null;
    }

    @Test
    public void testGetSigninMetaData() throws Exception {

        AzurePolicyMetaData result = metaDataClient.getSigninMetaData();
        assert result != null;
    }

    @Test
    public void testGetSignupMetaData() throws Exception {

        AzurePolicyMetaData result = metaDataClient.getSignupMetaData();
        assert result != null;
    }

    @Test
    public void testGetEditProfileMetaData() throws Exception {

        AzurePolicyMetaData result = metaDataClient.getEditProfileMetaData();
        assert result != null;
    }

    @Test
    public void testGetSignInRsaKey() throws IOException {

        byte[] key = rsaKeyClient.getSigninRsaKey();
        assert key != null;
    }
}