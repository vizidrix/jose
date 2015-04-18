

## TODO:

Add additional features:
- Option to set skew - variance allowed by clock time checks
- Option to provide time - to keep the library pure
- QueryStringHash string `json:"qsh"`
	- Hash producded from the Method, Relative Path plus the Sorted Set of Query String Params, used to prevent URL tampering
