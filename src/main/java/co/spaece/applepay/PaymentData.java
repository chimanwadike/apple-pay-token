package co.spaece.applepay;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Mirrors the Apple's PKPaymentData class
 */
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
	
	public String getApplicationPrimaryAccountNumber() {
		return applicationPrimaryAccountNumber;
	}
	
	public String getApplicationExpirationDate() {
		return applicationExpirationDate;
	}
	
	public String getCurrencyCode() {
		return currencyCode;
	}
	
	public Float getTransactionAmount() {
		return transactionAmount;
	}
	
	public String getCardholderName() {
		return cardholderName;
	}
	
	public String getDeviceManufacturerIdentifier() {
		return deviceManufacturerIdentifier;
	}
	
	public String getPaymentDataType() {
		return paymentDataType;
	}
	
	public String getMerchantTokenIdentifier() {
		return merchantTokenIdentifier;
	}
	
	public DetailedPaymentData getPaymentData() {
		return paymentData;
	}
	
	Date signingDate;
	
	/**
	 * Derived signing date from token decryption process.
	 * Not part of original Apple's PKPaymentData
	 * @return Date
	 */
	public Date getSigningDate() {
		return signingDate;
	}
	
	void setSigningDate(Date signingDate) {
		this.signingDate = signingDate;
	}
}
