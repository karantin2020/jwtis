package main

import (
	"errors"
)

var (
	errDBNotSet    = errors.New("repo db pointer is nil")
	errKeyNotFound = errors.New("requested key was not found in db")

	errLoadDBConf = errors.New("configs were not loaded from db")
	errSaveDBConf = errors.New("configs were not saved to db")

	errLoadDBInternal = errors.New("internal info was not loaded from db")
	errSaveDBInternal = errors.New("internal info was not saved to db")
)
