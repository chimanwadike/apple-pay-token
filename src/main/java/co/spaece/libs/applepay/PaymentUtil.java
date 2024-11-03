package co.spaece.libs.applepay;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

public interface PaymentUtil {
	PaymentData decryptPaymentToken(PaymentToken paymentToken, String appleMerchantPrivateKeyPath) throws CertificateException, KeyStoreException, IOException,
			NoSuchAlgorithmException, NoSuchProviderException;
}
