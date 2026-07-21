package cipher

var KeyData = &keyData{}

type keyData struct{}

func (*keyData) Key1CAFBCBAD() []byte  { return []byte{85, 72, 91, 122, 124, 109, 62, 42, 108, 86, 77, 45, 34, 103, 86, 77} }
func (*keyData) Key2CAFBCBAD() []byte  { return []byte{78, 37, 83, 113, 95, 122, 90, 92, 96, 69, 99, 72, 102, 36, 101, 80} }
func (*keyData) IvCAFBCBAD() []byte    { return []byte{84, 103, 112, 117, 96, 115, 90, 92, 105, 64, 66, 102, 115, 90, 125, 94} }
func (*keyData) Key1A474B1C2() []byte  { return []byte{58, 113, 124, 76, 81, 79, 60, 106, 46, 67, 122, 67, 59, 86, 87, 89} }
func (*keyData) Key2A474B1C2() []byte  { return []byte{114, 110, 37, 65, 69, 47, 65, 84, 39, 75, 59, 59, 89, 37, 82, 36} }
func (*keyData) Key15BFBA864() []byte  { return []byte{94, 103, 114, 121, 40, 80, 71, 117, 109, 72, 99, 116, 93, 41, 33, 60, 126, 107, 86, 41, 79, 33, 82, 64} }
func (*keyData) Key25BFBA864() []byte  { return []byte{99, 115, 99, 38, 114, 92, 94, 115, 107, 96, 116, 81, 123, 116, 118, 125, 63, 89, 46, 109, 111, 100, 62, 105} }
func (*keyData) Iv5BFBA864() []byte    { return []byte{119, 45, 86, 81, 40, 73, 126, 87} }
func (*keyData) Key16E0B65FF() []byte  { return []byte{37, 106, 99, 90, 70, 63, 38, 100, 83, 122, 46, 91, 36, 76, 98, 103, 43, 45, 103, 104, 67, 116, 105, 81} }
func (*keyData) Key26E0B65FF() []byte  { return []byte{89, 40, 91, 126, 125, 38, 116, 73, 72, 118, 89, 88, 98, 117, 81, 85, 38, 115, 85, 92, 103, 82, 46, 108} }
func (*keyData) KeyB809531F() []byte   { return []byte{79, 63, 37, 112, 83, 43, 75, 89, 59, 93, 91, 33, 58, 65, 122, 72} }
func (*keyData) IvB809531F() []byte    { return []byte{65, 60, 122, 85, 74, 33, 72, 61, 93, 45, 36, 69, 69, 60, 87, 121} }
func (*keyData) KeyF3974434() []byte   { return []byte{40, 47, 41, 37, 111, 60, 117, 72, 109, 76, 46, 81, 85, 39, 34, 45} }
func (*keyData) IvF3974434() []byte    { return []byte{104, 60, 66, 81, 90, 70, 58, 82, 103, 119, 126, 110, 105, 112, 72, 94} }
func (*keyData) KeyED382482() []byte   { return []byte{83, 47, 121, 74, 78, 121, 116, 77, 103, 102, 87, 90, 45, 68, 92, 87} }
func (*keyData) Key1B3047D4E() []int32 { return []int32{0x7A7A676A, 662588019, 1044588908, 1467841914} }
func (*keyData) Key2B3047D4E() []int32 { return []int32{1027369311, 1903786612, 1147098979, 1869162341} }
func (*keyData) Key3B3047D4E() []int32 { return []int32{1532651581, 777464439, 1246184549, 1715306076} }
func (*keyData) Key1C32C68F9() []int32 { return []int32{2037217365, 695935829, 1484616302, 1295860771} }
func (*keyData) Key2C32C68F9() []int32 { return []int32{2087735901, 1515740477, 1094598697, 678780266} }
func (*keyData) Key3C32C68F9() []int32 { return []int32{1113481070, 1182092836, 1350247229, 761546305} }
func (*keyData) IvC32C68F9() []int32   { return []int32{1414278975, 1867010337} }
