package nockchain

// SelectTransfer selects sufficient inputs by amount, then Base58 note name.
func SelectTransfer(sender ExtendedKey, notes []UnspentNote, payments []Payment, options TransferOptions) (PreparedTransfer, error) {
	return prepareTransfer(sender, notes, payments, options, false)
}

// Notes returns a detached copy of the selected complete input records.
func (p PreparedTransfer) Notes() []NoteV1 { return append([]NoteV1(nil), p.notes...) }
