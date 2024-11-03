package co.spaece.libs.applepay;

class PaymentUtilImpl implements PaymentUtil {
	private final String appleRootCACertificatePath;
	private final String appleMerchantPrivateKeyPath;
	
	PaymentUtilImpl(String appleRootCACertificatePath, String appleMerchantPrivateKeyPath) {
		this.appleRootCACertificatePath = appleRootCACertificatePath;
		this.appleMerchantPrivateKeyPath = appleMerchantPrivateKeyPath;
	}
	
	@Override
	public PaymentData decryptPaymentToken(PaymentToken paymentToken) {
		return null;
	}
}
