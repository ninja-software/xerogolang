package model

//Invoice is an Accounts Payable or Accounts Recievable document in a Xero organisation
type Invoice struct {
	// See Invoice Types
	Type string `json:"Type" xml:"Type"`

	// See Contacts
	Contact Contact `json:"Contact" xml:"Contact"`

	// See LineItems
	LineItems []LineItem `json:"LineItems>LineItem" xml:"LineItems>LineItem"`

	// Date invoice was issued – YYYY-MM-DD. If the Date element is not specified it will default to the current date based on the timezone setting of the organisation
	Date string `json:"Date,omitempty" xml:"Date,omitempty"`

	// Date invoice is due – YYYY-MM-DD
	DueDate string `json:"DueDate,omitempty" xml:"DueDate,omitempty"`

	// Line amounts are exclusive of tax by default if you don’t specify this element. See Line Amount Types
	LineAmountTypes string `json:"LineAmountTypes,omitempty" xml:"LineAmountTypes,omitempty"`

	// ACCREC – Unique alpha numeric code identifying invoice (when missing will auto-generate from your Organisation Invoice Settings) (max length = 255)
	InvoiceNumber string `json:"InvoiceNumber,omitempty" xml:"InvoiceNumber,omitempty"`

	// ACCREC only – additional reference number (max length = 255)
	Reference string `json:"Reference,omitempty" xml:"Reference,omitempty"`

	// See BrandingThemes
	BrandingThemeID string `json:"BrandingThemeID,omitempty" xml:"BrandingThemeID,omitempty"`

	// URL link to a source document – shown as “Go to [appName]” in the Xero app
	URL string `json:"Url,omitempty" xml:"Url,omitempty"`

	// The currency that invoice has been raised in (see Currencies)
	CurrencyCode string `json:"CurrencyCode,omitempty" xml:"CurrencyCode,omitempty"`

	// The currency rate for a multicurrency invoice. If no rate is specified, the XE.com day rate is used. (max length = [18].[6])
	CurrencyRate float32 `json:"CurrencyRate,omitempty" xml:"CurrencyRate,omitempty"`

	// See Invoice Status Codes
	Status string `json:"Status,omitempty" xml:"Status,omitempty"`

	// Boolean to set whether the invoice in the Xero app should be marked as “sent”. This can be set only on invoices that have been approved
	SentToContact bool `json:"SentToContact,omitempty" xml:"SentToContact,omitempty"`

	// Shown on sales invoices (Accounts Receivable) when this has been set
	ExpectedPaymentDate string `json:"ExpectedPaymentDate,omitempty" xml:"ExpectedPaymentDate,omitempty"`

	// Shown on bills (Accounts Payable) when this has been set
	PlannedPaymentDate string `json:"PlannedPaymentDate,omitempty" xml:"PlannedPaymentDate,omitempty"`

	// Total of invoice excluding taxes
	SubTotal float32 `json:"SubTotal,omitempty" xml:"SubTotal,omitempty"`

	// Total tax on invoice
	TotalTax float32 `json:"TotalTax,omitempty" xml:"TotalTax,omitempty"`

	// Total of Invoice tax inclusive (i.e. SubTotal + TotalTax). This will be ignored if it doesn’t equal the sum of the LineAmounts
	Total float32 `json:"Total,omitempty" xml:"Total,omitempty"`

	// Total of discounts applied on the invoice line items
	TotalDiscount float32 `json:"TotalDiscount,omitempty" xml:"TotalDiscount,omitempty"`

	// Xero generated unique identifier for invoice
	InvoiceID string `json:"InvoiceID,omitempty" xml:"InvoiceID,omitempty"`

	// boolean to indicate if an invoice has an attachment
	HasAttachments bool `json:"HasAttachments,omitempty" xml:"HasAttachments,omitempty"`

	// See Payments
	Payments []Payment `json:"Payments,omitempty" xml:"Payments,omitempty"`

	// See Prepayments
	Prepayments []Prepayment `json:"Prepayments,omitempty" xml:"Prepayments,omitempty"`

	// See Overpayments
	Overpayments []Overpayment `json:"Overpayments,omitempty" xml:"Overpayments,omitempty"`

	// Amount remaining to be paid on invoice
	AmountDue float32 `json:"AmountDue,omitempty" xml:"AmountDue,omitempty"`

	// Sum of payments received for invoice
	AmountPaid float32 `json:"AmountPaid,omitempty" xml:"AmountPaid,omitempty"`

	// The date the invoice was fully paid. Only returned on fully paid invoices
	FullyPaidOnDate string `json:"FullyPaidOnDate,omitempty" xml:"FullyPaidOnDate,omitempty"`

	// Sum of all credit notes, over-payments and pre-payments applied to invoice
	AmountCredited float32 `json:"AmountCredited,omitempty" xml:"AmountCredited,omitempty"`

	// Last modified date UTC format
	UpdatedDateUTC string `json:"UpdatedDateUTC,omitempty" xml:"UpdatedDateUTC,omitempty"`

	// Details of credit notes that have been applied to an invoice
	CreditNotes []CreditNote `json:"CreditNotes,omitempty" xml:"CreditNotes,omitempty"`
}

//Invoices contains a collection of Invoices
type Invoices struct {
	Invoices []Invoice `json:"Invoices" xml:"Invoice"`
}
