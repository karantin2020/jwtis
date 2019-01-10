package main

import (
	"errors"
)

var (
	errDBNotSet         = errors.New("repo db pointer is nil")
	errKeyNotFound      = errors.New("requested key was not found in db")
	errEncKeyNotFound   = errors.New("requested enc key was not found in db")
	errCheckKeyNotFound = errors.New("requested check key was not found in db")

	errLoadDBConf = errors.New("configs were not loaded from db")
	errSaveDBConf = errors.New("configs were not saved to db")

	errLoadDBInternal = errors.New("internal info was not loaded from db")
	errSaveDBInternal = errors.New("internal info was not saved to db")

	errIncorrectPassword   = errors.New("inserted password is not equal to db password")
	errDecryptDBCheckValue = errors.New("error decrypting dbCheckValue")
)
