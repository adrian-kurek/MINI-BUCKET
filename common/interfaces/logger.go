package interfaces

type Logger interface {
	Info(message string, data any)
	Error(message string, data any)
}
