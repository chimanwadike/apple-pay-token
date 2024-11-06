package co.spaece.applepay;

/**
 * Factory for creating instance of {@link PaymentUtil}
 */
public final class PaymentUtilFactory {
	
	private PaymentUtilFactory() {
	
	}
	
	/**
	 * Creates an instance of {@link PaymentUtil}
	 * @param appleRootCACertificatePath file path to .cer public certificate (e.g. Apple CA G3)
	 * @param appleMerchantPrivateKeyPath file path to .p12 or .jks merchant private key certificate
	 * @return {@link PaymentUtil}
	 */
	public static PaymentUtil getPaymentUtil(String appleRootCACertificatePath, String appleMerchantPrivateKeyPath) {
		return new PaymentUtilImpl(appleRootCACertificatePath, appleMerchantPrivateKeyPath);
	}
}
