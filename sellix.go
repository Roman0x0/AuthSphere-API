package main

type Subscription struct {
	Event string `json:"event"`
	Data  struct {
		ID           string `json:"id"`
		ShopID       int    `json:"shop_id"`
		Status       string `json:"status"`
		Gateway      string `json:"gateway"`
		CustomFields struct {
			UserID string `json:"userid"`
		} `json:"custom_fields"`
		CustomerID                    string      `json:"customer_id"`
		StripeCustomerID              string      `json:"stripe_customer_id"`
		StripeSubscriptionID          string      `json:"stripe_subscription_id"`
		StripeAccount                 string      `json:"stripe_account"`
		PaypalSubscriptionID          interface{} `json:"paypal_subscription_id"`
		PaypalAccount                 interface{} `json:"paypal_account"`
		ProductID                     string      `json:"product_id"`
		CouponID                      interface{} `json:"coupon_id"`
		CurrentPeriodEnd              int         `json:"current_period_end"`
		UpcomingEmail1WeekSent        int         `json:"upcoming_email_1_week_sent"`
		TrialPeriodEndingEmailSent    int         `json:"trial_period_ending_email_sent"`
		RenewalInvoiceCreated         int         `json:"renewal_invoice_created"`
		CreatedAt                     int64       `json:"created_at"`
		UpdatedAt                     interface{} `json:"updated_at"`
		CanceledAt                    interface{} `json:"canceled_at"`
		ShopName                      interface{} `json:"shop_name"`
		ProductTitle                  string      `json:"product_title"`
		CustomerName                  string      `json:"customer_name"`
		CustomerSurname               string      `json:"customer_surname"`
		CustomerPhone                 string      `json:"customer_phone"`
		CustomerPhoneCountryCode      string      `json:"customer_phone_country_code"`
		CustomerCountryCode           string      `json:"customer_country_code"`
		CustomerStreetAddress         string      `json:"customer_street_address"`
		CustomerAdditionalAddressInfo string      `json:"customer_additional_address_info"`
		CustomerCity                  string      `json:"customer_city"`
		CustomerPostalCode            string      `json:"customer_postal_code"`
		CustomerState                 string      `json:"customer_state"`
		CustomerEmail                 string      `json:"customer_email"`
		Invoices                      []struct {
			ID                 string `json:"id"`
			Uniqid             string `json:"uniqid"`
			RecurringBillingID string `json:"recurring_billing_id"`
			Total              string `json:"total"`
			TotalDisplay       string `json:"total_display"`
			ExchangeRate       string `json:"exchange_rate"`
			CryptoExchangeRate string `json:"crypto_exchange_rate"`
			Currency           string `json:"currency"`
			ShopID             string `json:"shop_id"`
			ProductID          string `json:"product_id"`
			Gateway            string `json:"gateway"`
			PaypalApm          string `json:"paypal_apm"`
			StripeApm          string `json:"stripe_apm"`
			Quantity           string `json:"quantity"`
			CouponID           string `json:"coupon_id"`
			Status             string `json:"status"`
			StatusDetails      string `json:"status_details"`
			VoidDetails        string `json:"void_details"`
			Discount           string `json:"discount"`
			CreatedAt          string `json:"created_at"`
			UpdatedAt          string `json:"updated_at"`
		} `json:"invoices"`
	} `json:"data"`
}
