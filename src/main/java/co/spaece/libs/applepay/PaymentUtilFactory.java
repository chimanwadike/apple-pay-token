package co.spaece.libs.applepay;

public final class PaymentUtilFactory {
	
	private PaymentUtilFactory() {
	
	}
	
	public static PaymentUtil getPaymentUtil(String appleRootCACertificatePath, String appleMerchantPrivateKeyPath) {
		return new PaymentUtilImpl(appleRootCACertificatePath, appleMerchantPrivateKeyPath);
	}
}
