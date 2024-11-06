package co.spaece.applepay;

/**
 * Factory for creating instance of {@link PaymentUtil}
 */
public final class PaymentUtilFactory {
	
	private PaymentUtilFactory() {
	
	}
	
	/**
	 * Creates an instance of {@link PaymentUtil}
	 * @param appleRootCACertificatePath
	 * @param appleMerchantPrivateKeyPath
	 * @return {@link PaymentUtil}
	 */
	public static PaymentUtil getPaymentUtil(String appleRootCACertificatePath, String appleMerchantPrivateKeyPath) {
		return new PaymentUtilImpl(appleRootCACertificatePath, appleMerchantPrivateKeyPath);
	}
}
