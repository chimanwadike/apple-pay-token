package co.spaece.libs.applepay;

public interface PaymentUtil {
	PaymentData decryptPaymentToken(PaymentToken paymentToken);
}
