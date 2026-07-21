package cipher

import "fmt"

func GetInstance(algoID string) (Interface, error) {
	switch algoID {
	case "CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E":
		return NewAESCBC(KeyData.Key1CAFBCBAD(), KeyData.Key2CAFBCBAD(), KeyData.IvCAFBCBAD()), nil
	case "A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4":
		return NewAESECB(KeyData.Key1A474B1C2(), KeyData.Key2A474B1C2()), nil
	case "5BFBA864-BBA9-42DB-8EAD-49B5F412BD81":
		return NewDESedeCBC(KeyData.Key15BFBA864(), KeyData.Key25BFBA864(), KeyData.Iv5BFBA864()), nil
	case "6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5":
		return NewDESedeECB(KeyData.Key16E0B65FF(), KeyData.Key26E0B65FF()), nil
	case "B809531F-0007-4B5B-923B-4BD560398113":
		return NewZUC(KeyData.KeyB809531F(), KeyData.IvB809531F()), nil
	case "F3974434-C0DD-4C20-9E87-DDB6814A1C48":
		return NewSM4CBC(KeyData.KeyF3974434(), KeyData.IvF3974434()), nil
	case "ED382482-F72C-4C41-A76D-28EEA0F1F2AF":
		return NewSM4ECB(KeyData.KeyED382482()), nil
	case "B3047D4E-67DF-4864-A6A5-DF9B9E525C79":
		return NewModXTEA(KeyData.Key1B3047D4E(), KeyData.Key2B3047D4E(), KeyData.Key3B3047D4E()), nil
	case "C32C68F9-CA81-4260-A329-BBAFD1A9CCD1":
		return NewModXTEAIV(KeyData.Key1C32C68F9(), KeyData.Key2C32C68F9(), KeyData.Key3C32C68F9(), KeyData.IvC32C68F9()), nil
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algoID)
	}
}
