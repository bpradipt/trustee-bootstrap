# Test resource policy for kind-kata-swtpm.sh verify. Releases a resource
# only to TPM evidence that the default AS policy marks affirming (trusted
# AK) and whose PCR8 holds the expected Init-Data digest. @PCR8@ is filled in
# by the script.
package policy

import rego.v1

default allow := false

allow if {
	cpu := input.submods.cpu0
	cpu["ear.status"] == "affirming"
	cpu["ear.veraison.annotated-evidence"].init_data == "@PCR8@"
}
