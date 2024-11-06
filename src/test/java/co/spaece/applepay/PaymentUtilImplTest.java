package co.spaece.applepay;

import static org.junit.jupiter.api.Assertions.*;

import java.io.FileNotFoundException;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;

public class PaymentUtilImplTest {
	private static final String APPLE_ROOT_CA_CERT_PATH = "/path/to/apple-root-ca-g3.cer";
	private static final String MERCHANT_PRIVATE_KEY_PATH = "/path/to/apple-pay.p12";
	private static final String PRIVATE_KEY_PASSWORD = "";
	
	@InjectMocks
	private PaymentUtilImpl paymentUtilImpl;
	
	private PaymentToken paymentToken;
	
	@BeforeEach
	public void setUp() throws JsonProcessingException {
		
		paymentToken = TestConstants.getPaymentToken();
		
		MockitoAnnotations.openMocks(this);
		// Initialize PaymentUtilImpl with mock certificate paths
		paymentUtilImpl = new PaymentUtilImpl(APPLE_ROOT_CA_CERT_PATH, MERCHANT_PRIVATE_KEY_PATH);
	}
	
	@Test
	public void testDecryptPaymentToken_invalidPath_throwsException() {
		// Act & Assert: Expect exception during decryption
		assertThrows(FileNotFoundException.class, () -> {
			paymentUtilImpl.decryptPaymentToken(paymentToken, PRIVATE_KEY_PASSWORD);
		}, "Invalid data should throw RuntimeException during decryption");
	}
	
	@Test
	public void testInitializePrivateCertificateKeyStore_invalidPath_throwsException() {
		// Act & Assert: Expect KeyStoreException when an invalid path is provided
		assertThrows(FileNotFoundException.class, () -> {
			paymentUtilImpl.initializePrivateCertificateKeyStore("invalid/path", PRIVATE_KEY_PASSWORD);
		}, "Invalid certificate path should throw KeyStoreException");
	}
	
	//	@Test
	//	public void testDecryptPaymentToken_success() throws Exception {
	//		// Act: Attempt to decrypt token
	//		PaymentData result = paymentUtilImpl.decryptPaymentToken(paymentToken, PRIVATE_KEY_PASSWORD);
	//
	//		// Assert: Verify output and decryption
	//		assertNotNull(result, "Decryption should produce a non-null PaymentData object");
	//	}
}
