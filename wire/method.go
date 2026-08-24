package wire

// Evidence class derivation (SPEC §7.4). The class is never transmitted:
// the receiver derives it from method_id through this fixed table, and
// any method_id outside the table falls to the Inference floor
// (BE-EVID-13 — unknown mechanisms get the lowest ceiling, never the
// benefit of the doubt).
//
// The integers are normative, not the decimals (SPEC §7.2): none of the
// ceilings is exactly representable in q8, comparisons use the integer
// column, conversions round toward zero.

type Class int

const (
	Inference Class = iota
	Documentation
	ExpertTestimony
	DirectObservation
)

func (c Class) String() string {
	switch c {
	case DirectObservation:
		return "DirectObservation"
	case ExpertTestimony:
		return "ExpertTestimony"
	case Documentation:
		return "Documentation"
	default:
		return "Inference"
	}
}

// Ceiling values in q8 fixed point (confidence × 255, floor).
const (
	CeilingDirectObservation uint8 = 242 // 0.95
	CeilingExpertTestimony   uint8 = 216 // 0.85
	CeilingDocumentation     uint8 = 191 // 0.75
	CeilingInference         uint8 = 165 // 0.65
)

// MethodSubprocess..MethodDerived are the defined method ids (SPEC §7.4).
const (
	MethodSubprocess    byte = 1 // subprocess executed now; exit + output captured
	MethodFileRead      byte = 2 // file read now from local storage
	MethodNetworkFetch  byte = 3 // network request issued now
	MethodDatabaseQuery byte = 4 // database query executed now
	MethodStaticConfig  byte = 5 // static configuration or documentation read
	MethodToolSchema    byte = 6 // a tool's own declared description or schema
	MethodSignedExpert  byte = 7 // statement signed by a declared domain identity
	MethodDerived       byte = 8 // derived from other spans; nothing observed
)

// ClassOf derives the evidence class and its q8 ceiling from a method id.
func ClassOf(methodID byte) (Class, uint8) {
	switch methodID {
	case MethodSubprocess, MethodFileRead, MethodNetworkFetch, MethodDatabaseQuery:
		return DirectObservation, CeilingDirectObservation
	case MethodStaticConfig, MethodToolSchema:
		return Documentation, CeilingDocumentation
	case MethodSignedExpert:
		return ExpertTestimony, CeilingExpertTestimony
	default:
		// BE-EVID-13: unknown falls to the floor.
		return Inference, CeilingInference
	}
}
