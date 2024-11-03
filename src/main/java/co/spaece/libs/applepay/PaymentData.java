package co.spaece.libs.applepay;

import com.fasterxml.jackson.annotation.JsonProperty;

public class PaymentData {
	@JsonProperty("applicationPrimaryAccountNumber")
	String applicationPrimaryAccountNumber;
	
	@JsonProperty("applicationExpirationDate")
	String applicationExpirationDate;
	
	@JsonProperty("currencyCode")
	String currencyCode;
	
	@JsonProperty("transactionAmount")
	Float transactionAmount;
	
	@JsonProperty("cardholderName")
	String cardholderName;
	
	@JsonProperty("deviceManufacturerIdentifier")
	String deviceManufacturerIdentifier;
	
	@JsonProperty("paymentDataType")
	String paymentDataType;
	
	@JsonProperty("merchantTokenIdentifier")
	String merchantTokenIdentifier;
	
	@JsonProperty("paymentData")
	DetailedPaymentData paymentData;
	
	public static class DetailedPaymentData{
		@JsonProperty("onlinePaymentCryptogram")
		String onlinePaymentCryptogram;
		
		public String getOnlinePaymentCryptogram() {
			return onlinePaymentCryptogram;
		}
		
		public void setOnlinePaymentCryptogram(String onlinePaymentCryptogram) {
			this.onlinePaymentCryptogram = onlinePaymentCryptogram;
		}
	}
	
}
