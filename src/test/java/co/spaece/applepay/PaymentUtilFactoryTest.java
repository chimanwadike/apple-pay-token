package co.spaece.applepay;

import org.junit.jupiter.api.Test;

public class PaymentUtilFactoryTest {
	@Test
	public void testCreatePaymentUtil() {
		PaymentUtil paymentUtil = PaymentUtilFactory.getPaymentUtil("/appleCA-G3.cer", "/merchantPrivate.p12");
		
		assert(paymentUtil instanceof PaymentUtilImpl);
	}
	
}
