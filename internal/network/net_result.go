package network

import "fmt"

type NetResult struct {
	Data      []byte
	Error     string
	IsSuccess bool
}

func SuccessResult(data []byte) NetResult {
	return NetResult{Data: data, IsSuccess: true}
}

func ErrorResult(err string) NetResult {
	return NetResult{Error: err, IsSuccess: false}
}

func (r NetResult) String() string {
	if r.IsSuccess {
		return fmt.Sprintf("Success[data=%s]", string(r.Data))
	}
	return fmt.Sprintf("Error[exception=%s]", r.Error)
}
