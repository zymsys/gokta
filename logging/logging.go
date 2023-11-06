package logging

import "fmt"
import "log"
import "strings"

type Logger interface {
	Debug(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
}

type LogFunc func(args ...interface{})

func LogAndReturnError(logFunc LogFunc, args ...interface{}) error {
	var errMsg error

	if len(args) > 0 {
		// Check if the last argument is an error that needs to be wrapped
		if err, ok := args[len(args)-1].(error); ok {
			// Create a new error message wrapping the original error
			errMsg = fmt.Errorf(strings.Trim(fmt.Sprint(args[:len(args)-1]...), "[]"), err)
		} else {
			// Create a simple error message
			errMsg = fmt.Errorf(fmt.Sprint(args...))
		}
	} else {
		errMsg = fmt.Errorf("unknown error")
	}

	logFunc(errMsg)
	return errMsg
}

type NoOpLogger struct{}

func (l NoOpLogger) Debug(args ...interface{}) {}
func (l NoOpLogger) Info(args ...interface{})  {}
func (l NoOpLogger) Warn(args ...interface{})  {}
func (l NoOpLogger) Error(args ...interface{}) {}

type StandardLogger struct{}

func (l StandardLogger) Debug(args ...interface{}) {
	log.Println(append([]interface{}{"DEBUG:"}, args...)...)
}

func (l StandardLogger) Info(args ...interface{}) {
	log.Println(append([]interface{}{"INFO:"}, args...)...)
}

func (l StandardLogger) Warn(args ...interface{}) {
	log.Println(append([]interface{}{"WARN:"}, args...)...)
}

func (l StandardLogger) Error(args ...interface{}) {
	log.Println(append([]interface{}{"ERROR:"}, args...)...)
}
