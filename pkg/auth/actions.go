package auth

type Action string

const (
	Recovery Action = "recovery"
	Activation Action = "activation"
)