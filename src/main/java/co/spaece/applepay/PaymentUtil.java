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
	 * Used to decrypt a payment token and return a payment data object
	 * @param paymentToken token obtain from apple
	 * @param privateKeyPassword private key password or empty string if no password
	 * @return {@link PaymentData}
	 * @throws CertificateException certificate-related exceptions
	 * @throws KeyStoreException keystore-related exceptions
	 * @throws IOException IO-related exceptions
	 * @throws NoSuchAlgorithmException key-algorithm-related exceptions
	 * @throws NoSuchProviderException key-algorithm-related exceptions
	 */
	PaymentData decryptPaymentToken(PaymentToken paymentToken, String privateKeyPassword) throws CertificateException, KeyStoreException, IOException,
			NoSuchAlgorithmException, NoSuchProviderException;
}
