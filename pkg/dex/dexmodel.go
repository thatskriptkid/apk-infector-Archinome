package dex

// In-memory model of a dex file.
//
// Everything the writer needs to rewrite a dex lives here: the four sorted
// identifier tables, the class definitions, and every data item they point at,
// with cross-references kept as *old* indices. The encoder builds new (sorted,
// deduplicated) index spaces and translates every reference through the old→new
// maps, which is what lets it rename a type descriptor that moves position in
// the string pool.
//
// Index fields are always "index into the corresponding table of the parsed
// file", except where noted (class_data entries index field_ids/method_ids,
// exactly like the on-disk encoded_field/encoded_method do).

// NoIndex marks an absent reference (0xffffffff in the file).
const NoIndex = 0xffffffff

type Proto struct {
	Shorty uint32   // string index
	Return uint32   // type index
	Params []uint32 // type indices; nil when parameters_off == 0
}

type Field struct {
	Class uint32 // type index
	Type  uint32 // type index
	Name  uint32 // string index
}

type Method struct {
	Class uint32 // type index
	Proto uint32 // proto index
	Name  uint32 // string index
}

// TryItem is a try_item: the range of covered code units plus the handler list.
type TryItem struct {
	StartAddr  uint32
	InsnCount  uint16
	HandlerIdx uint16
}

// CatchHandler is one entry of an encoded_catch_handler. Type == NoIndex marks
// the catch-all entry, which must be the last one.
type CatchHandler struct {
	Type uint32
	Addr uint32
}

// dbgKind describes how a debug_info state machine operand is interpreted, so
// that the encoder knows which operand to translate through which index map.
type dbgKind uint8

const (
	dbgPlain  dbgKind = iota // plain unsigned LEB128
	dbgString                // string index
	dbgType                  // type index
	dbgSigned                // signed LEB128
)

// DbgOp is one state machine bytecode of a debug_info_item.
type DbgOp struct {
	Op   uint32
	Args []uint32
	Kind []dbgKind
}

// DebugInfo is a debug_info_item.
type DebugInfo struct {
	LineStart uint32
	Params    []uint32 // string indices, NoIndex allowed
	Ops       []DbgOp
}

// CodeItem is a code_item.
type CodeItem struct {
	Registers uint16
	Ins       uint16
	Outs      uint16
	Insns     []uint16
	Tries     []TryItem
	Handlers  [][]CatchHandler
	Debug     *DebugInfo
}

type EncField struct {
	Field  uint32 // field_ids index
	Access uint32
}

type EncMethod struct {
	Method uint32 // method_ids index
	Access uint32
	Code   *CodeItem // nil when code_off == 0
}

type ClassData struct {
	StaticFields   []EncField
	InstanceFields []EncField
	DirectMethods  []EncMethod
	VirtualMethods []EncMethod
}

// EncodedValue is one encoded_value. Type is the low 5 bits of the tag; the
// payload lives in Int (raw bit pattern for numeric, index and boolean values),
// Arr or Ann.
type EncodedValue struct {
	Type byte
	Int  uint64 // numeric payload / index value / boolean 0|1
	Arr  []EncodedValue
	Ann  *EncodedAnnotation
}

type AnnotationElement struct {
	Name  uint32 // string index
	Value EncodedValue
}

type EncodedAnnotation struct {
	Type     uint32 // type index
	Elements []AnnotationElement
}

type AnnotationItem struct {
	Visibility byte
	Ann        EncodedAnnotation
}

type AnnotatedField struct {
	Field uint32 // field_ids index
	Anns  []AnnotationItem
}

type AnnotatedMethod struct {
	Method uint32 // method_ids index
	Anns   []AnnotationItem
}

type AnnotatedParameter struct {
	Method uint32 // method_ids index
	Anns   [][]AnnotationItem
}

type AnnotationsDirectory struct {
	Class      []AnnotationItem
	Fields     []AnnotatedField
	Methods    []AnnotatedMethod
	Parameters []AnnotatedParameter
}

func (a *AnnotationsDirectory) empty() bool {
	return a == nil || (len(a.Class) == 0 && len(a.Fields) == 0 &&
		len(a.Methods) == 0 && len(a.Parameters) == 0)
}

type ClassDef struct {
	ClassIdx     uint32 // type index
	AccessFlags  uint32
	Superclass   uint32 // type index, NoIndex allowed
	Interfaces   []uint32
	SourceFile   uint32 // string index, NoIndex allowed
	Annotations  *AnnotationsDirectory
	ClassData    *ClassData
	StaticValues []EncodedValue // nil when static_values_off == 0
}

// DexFile is a fully decoded dex file.
type DexFile struct {
	Version string
	Strings []string
	Types   []uint32
	Protos  []Proto
	Fields  []Field
	Methods []Method
	Classes []ClassDef
}
