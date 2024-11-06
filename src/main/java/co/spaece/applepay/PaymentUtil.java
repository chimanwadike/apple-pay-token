package co.spaece.applepay;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

/**
 * Decrypts an Apple Pay token using with the merchant's private key password
 */
public interface PaymentUtil {
	
	/**
	 *
	 * @param paymentToken
	 * @param privateKeyPassword
	 * @return {@link PaymentData}
	 * @throws CertificateException
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	PaymentData decryptPaymentToken(PaymentToken paymentToken, String privateKeyPassword) throws CertificateException, KeyStoreException, IOException,
			NoSuchAlgorithmException, NoSuchProviderException;
}
