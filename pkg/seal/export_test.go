package seal

import "io"

// CappedWriter is the writer Seal encrypts into.
func CappedWriter(w io.Writer) io.Writer { return &capped{w: w} }
