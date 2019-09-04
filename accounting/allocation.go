package accounting

//Allocation allocated an overpayment or Prepayment to an Invoice
type Allocation struct {

	// note: the Amount for GET and PUT uses similar but differnt naming

	// the amount being applied to the invoice (GET)
	// https://developer.xero.com/documentation/api/overpayments#GET
	Amount float64 `json:"Amount,omitempty" xml:"Amount,omitempty"`

	// the amount being applied to the invoice (PUT)
	// https://developer.xero.com/documentation/api/overpayments#PUT
	AppliedAmount float64 `json:"AppliedAmount,omitempty" xml:"AppliedAmount,omitempty"`

	// the date the prepayment is applied YYYY-MM-DD (read-only). This will be the latter of the invoice date and the prepayment date.
	Date string `json:"Date,omitempty" xml:"-"`

	//The Invoice that the allocation will be made to
	Invoice InvoiceID `json:"Invoice,omitempty" xml:"Invoice>InvoiceID,omitempty"`
}

//Allocations is a collection of Allocations
type Allocations struct {
	Allocations []Allocation `json:"Allocations" xml:"Allocation"`
}
